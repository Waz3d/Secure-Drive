#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <limits.h> // for INT_MAX
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

using namespace std;

#define SERVER_PORT 5000
#define BUF_LEN     1000000
#define BLOCK_SIZE  4000000
#define REQUEST_LEN 12
#define STATUS_SIZE 4

FILE* file_to_download;
unsigned char* file_to_download_name;
int socket_holder;

struct CommunicationData {
    int fileDescriptor;
    unsigned char* sessionKey[2];
    unsigned int counter;
    int index;
};

EVP_PKEY* my_priv_key;
unsigned char* username;
CommunicationData* serverData;

void ctrlC_handler(int sig){
    if(file_to_download!=NULL){
        fclose(file_to_download);
        remove((char*)file_to_download_name);
        //free(file_to_upload_name);
    }
    //We define the handler after the initialise so my_priv_key is certainly set
    EVP_PKEY_free(my_priv_key);
    if(serverData!=NULL){
        free(serverData->sessionKey[0]);
        free(serverData->sessionKey[1]);
        free(serverData);
    }
    close(socket_holder);
    exit(1);
}
 
void handleErrorsInAuthenticate(int socket) {
    printf("[-] There was an error during authentication\n");
    close(socket);
    EVP_PKEY_free(my_priv_key);
    if (serverData != NULL) {
        free(serverData->sessionKey[0]);
        free(serverData->sessionKey[1]);
        free(serverData);
    }
    exit(1);
}

void handleErrors() {
    printf("[-] There was an error\n");
    EVP_PKEY_free(my_priv_key);
    if (serverData != NULL) {
        free(serverData->sessionKey[0]);
        free(serverData->sessionKey[1]);
        free(serverData);
    }
    exit(1);
}

void closeConnectionDueToError(int socket, const char* error){
    printf("[-] There was an error: %s...\n", error);
    close(socket);
    EVP_PKEY_free(my_priv_key);
    if (serverData != NULL) {
        free(serverData->sessionKey[0]);
        free(serverData->sessionKey[1]);
        free(serverData);
    }
    exit(1);
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return -1;
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;
	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return -1;
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        cout << "RET: " << ret << endl;
        return -1;
    }
}

int gcm_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag )
{
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len=0;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return -1;

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return -1;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int incrementCounter(int socket) {

    if (serverData->counter == UINT_MAX) {
        if(serverData->index == 1) {
            cout << "[-] Connection timed out" << endl;
            return -1;
        }
        serverData->index = 1;
        serverData->counter = 0;
        return 0;
    }
    serverData->counter++;
    return 0;
}

int rcvEncrypted (unsigned char *plaintext, int ciphertext_len, int socket){

    //CLIENT
    
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_gcm());

    int buffer_len = ciphertext_len + 16 + iv_len;
    unsigned char* buffer = (unsigned char*)malloc(buffer_len);
    if(!buffer){
        closeConnectionDueToError(socket, "error during malloc");
        return -1;
    }

    int len = 0;
    int ret;

    ret = recv(socket, buffer, buffer_len, MSG_WAITALL);
    if(ret <= 0){
        free(buffer);
        closeConnectionDueToError(socket, "error during receive");
        return -1;
    }
    
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    if(!ciphertext){
        free(buffer);
        closeConnectionDueToError(socket, "error during malloc");
        return -1;
    }
    memcpy(ciphertext, buffer, ciphertext_len);
    
    unsigned char* tag = (unsigned char*)malloc(16);
    if(!tag){
        free(buffer);
        free(ciphertext);
        closeConnectionDueToError(socket, "error during malloc");
        return -1;
    }
    memcpy(tag, buffer + ciphertext_len, 16);
    
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    if(!iv){
        free(buffer);
        free(ciphertext);
        free(tag);
        closeConnectionDueToError(socket, "error during malloc");
        return -1;
    }
    memcpy(iv, buffer + ciphertext_len + 16, iv_len);
    
    unsigned char* key = serverData->sessionKey[serverData->index];

    unsigned char* counter_str = (unsigned char*) malloc(sizeof(int));
    if(!counter_str){
        free(buffer);
        free(iv);
        free(ciphertext);
        free(tag);
        closeConnectionDueToError(socket, "error during malloc");
        return -1;
    }

    unsigned int counter = htonl(serverData->counter);
    memcpy(counter_str, (unsigned char*)&counter, sizeof(int));
    
    int plaintext_length = gcm_decrypt(ciphertext, ciphertext_len, counter_str, 4, tag, key, iv, iv_len, plaintext);
    if(plaintext_length==-1){
        free(buffer);
        free(ciphertext);
        free(tag);
        free(iv);
        free(counter_str);
        closeConnectionDueToError(socket, "error during decryption");
        return -1;
    }

    ret = incrementCounter(socket);
    free(buffer);
    free(ciphertext);
    free(tag);
    free(iv);
    free(counter_str);
    if(ret==-1){
        return -1;
    }

    return plaintext_length;

}

int sendEncryptedData(const unsigned char* plaintext, int plaintext_len, int socket, bool send_size, unsigned int n_blocks, unsigned int last_block_size, bool wait_response) { 

    int tag_len = 16;
    unsigned char* counter;
    unsigned char* key;
    unsigned char* tag;
    unsigned char* ciphertext;
    int ret;

    counter = (unsigned char*)malloc(sizeof(int));
    if (!counter) {
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    const EVP_CIPHER* cipher = EVP_aes_128_gcm();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    if (!iv) {
        free(counter);
        free(ciphertext);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    //Se devo inviare il numero di blocchi e la dimensione dell'ultimo
    //lo faccio qui
    if (send_size) {

        key = serverData->sessionKey[serverData->index];
        unsigned int net_counter = htonl(serverData->counter);
        memcpy(counter, (unsigned char*)&net_counter, sizeof(unsigned int));

        ciphertext = (unsigned char*)malloc(sizeof(int)*2 + 16);
        if(!ciphertext) {
            free(counter);
            free(iv);
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        tag = (unsigned char*)malloc(tag_len);
        if (!tag) {
            free(ciphertext);
            free(iv);
            free(counter);
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }

        RAND_poll();
        ret = RAND_bytes(iv, iv_len);
        if (ret <= 0) {
            free(ciphertext);
            free(counter);
            free(iv);
            free(tag);
            closeConnectionDueToError(socket, "Error generating iv");
            return -1;
        }

        unsigned char* info_len_buffer = (unsigned char*)malloc(sizeof(int)*2);
        if (!info_len_buffer) {
            free(ciphertext);
            free(counter);
            free(iv);
            free(tag);
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        unsigned int net_blocks = htonl(n_blocks);
        unsigned int net_block_size = htonl(last_block_size);
        memcpy(info_len_buffer, (unsigned char*)&net_blocks, sizeof(unsigned int));
        memcpy(info_len_buffer + sizeof(int), (unsigned char*)&net_block_size, sizeof(unsigned int));

        ret = gcm_encrypt(info_len_buffer, sizeof(int)*2, counter, sizeof(int), key, iv, iv_len, ciphertext, tag);
        free(info_len_buffer);

        if (ret == -1) {
            free(ciphertext);
            free(iv);
            free(counter);
            free(tag);
            closeConnectionDueToError(socket, "Error during encryption");
            return -1;
        }
        int ct_len = ret;

        unsigned char* info_to_send = (unsigned char*)malloc(ct_len + tag_len + iv_len);
        if (!info_to_send) {
            free(ciphertext);
            free(iv);
            free(counter);
            free(tag);
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        
        memcpy(info_to_send, ciphertext, ct_len);
        memcpy(info_to_send + ct_len, tag, tag_len);
        memcpy(info_to_send + ct_len + tag_len, iv, iv_len);

        ret = send(socket, info_to_send, ct_len + tag_len + iv_len, 0);
        free(info_to_send);
        free(tag);
        free(ciphertext);
        if (ret == -1) {
            free(ciphertext);
            free(iv);
            free(counter);
            closeConnectionDueToError(socket, "Error sending the message");
            return -1;
        }

        ret = incrementCounter(socket);
        if (ret == -1) {
            free(iv);
            free(counter);
            return -1;
        }

        key = serverData->sessionKey[serverData->index];

        unsigned char* status_buffer = (unsigned char*)malloc(STATUS_SIZE);
        if (!status_buffer) {
            free(iv);
            free(counter);
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }

        ret = rcvEncrypted(status_buffer, STATUS_SIZE, socket);
        if (ret == -1) {
            free(iv);
            free(counter);
            free(status_buffer);
            return -1;
        }

        if(strncmp((char*)status_buffer, "OKAY", 4) == 0) {
            cout << "[+] Data sent correctly...\n";
        }
        else if(strncmp((char*)status_buffer, "TBIG", 4) == 0) {
            free(status_buffer);
            free(iv);
            free(counter);
            cout << "[-] Error, file too big, server side...\n";
            return -2;
        }
        else if(strncmp((char*)status_buffer, "COPY", 4) == 0) {
            free(status_buffer);
            free(iv);
            free(counter);
            cout << "[-] Error, file already exists, server side...\n";
            return -2;
        }
        else if(strncmp((char*)status_buffer, "FILE", 4) == 0) {
            //This one will never be received by the server, it's here for portability
            //reasons only
            free(status_buffer);
            free(iv);
            free(counter);
            cout << "[-] Error, filename not valid, server side...\n";
            return -2;
        }

        free(status_buffer);

    }
    unsigned int net_counter = htonl(serverData->counter);
    memcpy(counter, (unsigned char*)&net_counter, sizeof(int));

    RAND_poll();
    ret = RAND_bytes(iv, iv_len);
    if (ret <= 0) {
        free(counter);
        free(iv);
        closeConnectionDueToError(socket, "Error generating iv");
        return -1;
    }

    //cifriamo il plaintext e lo inviamo
    ciphertext = (unsigned char*)malloc(plaintext_len + 16);
    if (!ciphertext) {
        free(counter);
        free(iv);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    key = serverData->sessionKey[serverData->index];

    tag = (unsigned char*)malloc(tag_len);
    if (!tag) {
        free(ciphertext);
        free(iv);
        free(counter);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    ret = gcm_encrypt(plaintext, plaintext_len, counter, 4, key, iv, iv_len, ciphertext, tag);
    if (ret == -1) {
        free(ciphertext);
        free(iv);
        free(counter);
        free(tag);
        closeConnectionDueToError(socket, "Error during encryption");
        return -1;
    }
    int ct_len = ret;


    unsigned char* buffer = (unsigned char*)malloc(ct_len + tag_len + iv_len);
    if (!buffer) {
        free(ciphertext);
        free(iv);
        free(counter);
        free(tag);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    memcpy(buffer, ciphertext, ct_len);
    free(ciphertext);
    memcpy(buffer + ct_len, tag, tag_len);
    free(tag);
    memcpy(buffer + ct_len + tag_len, iv, iv_len);
    free(iv);

    ret = send(socket, buffer, ct_len + tag_len + iv_len, 0);
    free(buffer);
    free(counter);
    if (ret == -1) {
        closeConnectionDueToError(socket, "Error sending the message");
        return -1;
    }

    ret = incrementCounter(socket);

    if (ret == -1) {
        return -1;
    }
    
    if (!wait_response) {
        return 0;
    }

    //Riassocia le key (se è cambiata), ricevi il messaggio di stato e comportati
    //di conseguenza, errori in cifratura, chiudi, altrimenti riparti
    key = serverData->sessionKey[serverData->index];

    unsigned char* status_buffer = (unsigned char*)malloc(STATUS_SIZE);
    if (!status_buffer) {
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    ret = rcvEncrypted(status_buffer, STATUS_SIZE, socket);
    if (ret <= 0) {
        free(status_buffer);
        return -1;
    }

    if(strncmp((char*)status_buffer, "OKAY", 4) == 0) {
        cout << "[+] Data sent correctly...\n";
    }
    else if(strncmp((char*)status_buffer, "TBIG", 4) == 0) {
        free(status_buffer);
        cout << "[-] Error, file too big, server side...\n";
        return -2;
    }
    else if(strncmp((char*)status_buffer, "COPY", 4) == 0) {
        free(status_buffer);
        cout << "[-] Error, file already exists, server side...\n";
        return -2;
    }
    else if(strncmp((char*)status_buffer, "FILE", 4) == 0) {
        //This one will never be received by the server, it's here for portability
        //reasons only
        free(status_buffer);
        cout << "[-] Error, filename not valid, server side...\n";
        return -2;
    }

    free(status_buffer);
    return 0;
}

EVP_PKEY* checkServerCert (const unsigned char* cert, int cert_len, int socket){

    BIO* serverCertBIO = BIO_new(BIO_s_mem());

    int ret = BIO_write(serverCertBIO, cert, cert_len);

    //Store certificate of server into X509 structure
    X509* serverCert = PEM_read_bio_X509(serverCertBIO, NULL, NULL, NULL);
    //Check wheter the certificate refers to the server or not
    char* nameServer = X509_NAME_oneline(X509_get_subject_name(serverCert), NULL, 0);

    ret = strcmp(nameServer, "/C=IT/CN=Server");
    if(ret!=0){
        cout << "Certificate doesn't belong to the server" << endl;
        handleErrorsInAuthenticate(socket);
    }
    free(nameServer);
    //Read the certicicate of CA and store it into X509 structure
    FILE* certCA_PEM = fopen("FoC_CA_cert.pem", "r");
    if (!certCA_PEM)
        handleErrorsInAuthenticate(socket);
    X509* certCA = PEM_read_X509(certCA_PEM, NULL, NULL, NULL);
    fclose(certCA_PEM);
    //Create the store
    X509_STORE * store = X509_STORE_new();
    ret = X509_STORE_add_cert(store, certCA);
    if(ret==-1){
        cout << "Cannot add the certificate to the store" << endl;
        handleErrorsInAuthenticate(socket);
    }
    
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();

    ret = X509_STORE_CTX_init(ctx, store, serverCert, NULL);
    if(ret==-1){
        cout << "Cannot initialize the certificate-verification context" << endl;
        handleErrorsInAuthenticate(socket);
    }

    ret = X509_verify_cert(ctx);
    if(ret<0){
        cout << "Error during the verification" << endl;
        handleErrorsInAuthenticate(socket);
    }else if(ret==0){
        cout << "Certificate can't be verified" << endl;
        handleErrorsInAuthenticate(socket);
    }
    cout << "[+] Certificate verified successfully...\n";

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    BIO_free(serverCertBIO);
    X509_free(certCA);
    EVP_PKEY* server_pkey = X509_get_pubkey(serverCert);
    X509_free(serverCert);
    return server_pkey;
}

void checkEncryptedSignature(EVP_PKEY* longterm_public_key, unsigned char* session_key, unsigned char* server_dhpkey, unsigned char* client_dhpkey, unsigned char* cipher_signature, int server_dhlenght, int client_dhlenght, int signature_len, unsigned char* iv, int iv_len, int socket){
    int ret; // used for return values

    //Create and initialise the context
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ 
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        handleErrorsInAuthenticate(socket);
    }
    ret = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), session_key, iv);
    if(ret != 1){
        cerr <<"Error: DecryptInit Failed\n";
        handleErrorsInAuthenticate(socket);
    }

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0; // total decrypted bytes

    //TODO: continuare
    unsigned char* signature = (unsigned char*)malloc(signature_len);
    if (!signature) {
        handleErrorsInAuthenticate(socket);
    }

    ret = EVP_DecryptUpdate(ctx, signature, &update_len, cipher_signature, signature_len);
    if(ret != 1){
        cerr <<"Error: DecryptUpdate Failed\n";
        handleErrorsInAuthenticate(socket);
    }
    total_len += update_len;
    //Decrypt Final. Finalize the Decryption and adds the padding
    
    ret = EVP_DecryptFinal(ctx, signature + total_len, &update_len);
    if(ret <= 0){
        cerr <<"Error: DecryptFinal Failed\n";
        handleErrorsInAuthenticate(socket);
    }
    
    total_len += update_len;
    int clear_size = total_len;

    // delete the context from memory:
    EVP_CIPHER_CTX_free(ctx);
    unsigned char* buf = (unsigned char *) malloc(server_dhlenght + client_dhlenght);
    if(!buf)
        handleErrorsInAuthenticate(socket);
    int buf_lenght = server_dhlenght + client_dhlenght;
    memcpy(buf, server_dhpkey, server_dhlenght);
    memcpy(buf+server_dhlenght, client_dhpkey, client_dhlenght);

    EVP_MD_CTX *ctx_sign = EVP_MD_CTX_new();
    ret = EVP_VerifyInit(ctx_sign, EVP_sha256());
    if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; handleErrorsInAuthenticate(socket); }
    
    ret = EVP_VerifyUpdate(ctx_sign, buf, buf_lenght);
    if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; handleErrorsInAuthenticate(socket); }
    
    ret = EVP_VerifyFinal(ctx_sign, signature, clear_size, longterm_public_key);
    if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        handleErrorsInAuthenticate(socket);
    }else if(ret == 0){
        cerr << "Error: Invalid signature!\n";
        handleErrorsInAuthenticate(socket);
    }
    cout << "[*] Correct signature..\n";
    free(buf);
    free(signature);
    EVP_MD_CTX_free(ctx_sign);
}

int generateEncryptedUsername(unsigned char* username, unsigned char* encrypted_username, EVP_PKEY* longterm_server_pkey, unsigned char* iv, unsigned char* encrypted_key, int socket){
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int encrypted_key_len = EVP_PKEY_size(longterm_server_pkey);

    int block_size = EVP_CIPHER_block_size(cipher);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){cerr<<"Error: EVP_CIPHER_CTX_new returned NULL\n"; handleErrorsInAuthenticate(socket);}

    int username_size = sizeof(username);
    if(username_size > INT_MAX - block_size){cerr<<"Error: integer overflow\n"; handleErrorsInAuthenticate(socket);}

    int ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &longterm_server_pkey, 1);
    if(ret <= 0){
        cerr<<"Error: EVP_SealInit returned" << ret << endl;
        handleErrorsInAuthenticate(socket);
    }

    int nc = 0; //bytes encrypted at each chunk
    int nctot = 0;  //total encrypted bytes

    ret = EVP_SealUpdate(ctx, encrypted_username, &nc, username, username_size);
    if(ret==0){cerr<<"Error: EVP_SealUpdate returned " << ret << endl; handleErrorsInAuthenticate(socket);}
    nctot += nc;

    ret = EVP_SealFinal(ctx, encrypted_username + nctot, &nc);
    if(ret==0){cerr<<"Error: EVP_SealFinal returned " << ret << endl; handleErrorsInAuthenticate(socket);}
    nctot += nc;
    int encrypted_username_size = nctot;

    EVP_CIPHER_CTX_free(ctx);

    return encrypted_username_size;
}

int upload(unsigned char* local_filename, const unsigned char* new_filename, int socket){

    //Check if new filename has got some undesired characters
    string name((char*)new_filename);
    const char okchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- àòèéù";
    if (name.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Invalid filename!...\n";
        return -1;
    }

    //Open file and write data into a buffer
    FILE* file = fopen((const char*)local_filename, "r");
    if(!file){
        cout << "[-] File doesn't exists!...\n";
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long int file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    int last_block_size = file_size % BLOCK_SIZE;
    int number_blocks;
    bool multiple; // Used to correctly send the last block
    if(last_block_size == 0){
        number_blocks = file_size/BLOCK_SIZE;
        multiple = true;
    }else{
        number_blocks = file_size/BLOCK_SIZE + 1;
        multiple = false;
    }

    int ret;

    int filename_len = strlen((char*)new_filename);
    const char str_op[] = "UPLO";
    unsigned char* info_buffer = (unsigned char*) malloc(REQUEST_LEN);
    if(!info_buffer){
        closeConnectionDueToError(socket, "error during malloc\n");
    }

    RAND_poll();
    ret = RAND_bytes(info_buffer, REQUEST_LEN);
    if (ret <= 0) {
        free(info_buffer);
        closeConnectionDueToError(socket, "Error generating message");
        return -1;
    }

    unsigned int htonl_len = htonl(filename_len);
    memcpy(info_buffer, str_op, strlen(str_op));
    memcpy(info_buffer + strlen(str_op), (unsigned char*)&htonl_len, sizeof(int));

    //Send operation code + length of filename + random bytes
    ret = sendEncryptedData(info_buffer, REQUEST_LEN, socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
    }
    else if(ret == -2) {
        return 0;
    }
    
    //Send filename and waits for status code!!!
    ret=sendEncryptedData(new_filename, filename_len, socket, false, 0, 0, true);
    if(ret==-1) {
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
    }
    else if(ret == -2) {
        return 0;
    }
    
    cout << "[+] Loading: " << endl;
    //fflush(stdout);
    int n = number_blocks / 10 + 1;
    for(int i = 0; i < number_blocks; i++){
        if(i%n==0){
            cout << "*";
            fflush(stdout);
        }
        
        unsigned char* send_buffer;
        if(!multiple && i == number_blocks - 1){
            cout << endl;
            send_buffer = (unsigned char*)malloc(last_block_size);
            if(!send_buffer){
                closeConnectionDueToError(socket, "error due to malloc\n");
            }

            int ret = fread(send_buffer, 1, last_block_size, file);
            if(ret < last_block_size){
                fclose(file);
                free(send_buffer);
                cout << "[-] Error while reading file!...\n";
                return -1;
            }
            
            ret = sendEncryptedData(send_buffer, last_block_size, socket, i == 0, number_blocks, last_block_size, i == (number_blocks - 1));
            if (ret == -1) {
                closeConnectionDueToError(socket, "error while sending data!...\n");
                return -1;
            }
            else if(ret == -2) {
                free(send_buffer);
                return 0;
            }
        }
        else{
            send_buffer = (unsigned char*)malloc(BLOCK_SIZE);
            if(!send_buffer){
                closeConnectionDueToError(socket, "error due to malloc\n");
            }

            int ret = fread(send_buffer, 1, BLOCK_SIZE, file);
            if(ret < BLOCK_SIZE){
                fclose(file);
                free(send_buffer);
                cout << "[-] Error while reading file!...\n";
                return -1;
            }
            
            ret = sendEncryptedData(send_buffer, BLOCK_SIZE, socket, i == 0, number_blocks, last_block_size, i == (number_blocks - 1));
            
            if (ret == -1) {
                closeConnectionDueToError(socket, " Error while sending data!...\n");
                return -1;
            }
            else if(ret == -2) {
                free(send_buffer);
                return 0;
            }
        }
        free(send_buffer);
    }
    fclose(file);
    return 0;
}

int renameFile(unsigned char* filename_old, unsigned char* filename_new, int socket){

    string new_name((char*)filename_new);
    const char okchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- àòèéù";
    if (new_name.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Invalid new filename!...\n";
        return -1;
    }

    string old_name((char*)filename_old);
    if (old_name.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Invalid old filename!...\n";
        return -1;
    }

    int ret;

    int filename_old_len = strlen((char*)filename_old);
    int filename_new_len = strlen((char*)filename_new);
    const char str_op[] = "RENA";
    unsigned char* info_buffer = (unsigned char*) malloc(REQUEST_LEN);
    if(!info_buffer){
        closeConnectionDueToError(socket, "error during malloc\n");
        return -1;
    }

    unsigned int htonl_len_old = htonl(filename_old_len);
    unsigned int htonl_len_new = htonl(filename_new_len);
    memcpy(info_buffer, str_op, strlen(str_op));
    memcpy(info_buffer + strlen(str_op), (unsigned char*)&htonl_len_old, sizeof(int));
    memcpy(info_buffer + strlen(str_op) + sizeof(int), (unsigned char*)&htonl_len_new, sizeof(int));
    
    ret = sendEncryptedData(info_buffer, REQUEST_LEN, socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return -1;
    }
    else if(ret == -2) {
        return 0;
    }

    unsigned char* filenames = (unsigned char*) malloc(filename_new_len+filename_old_len);
    if(!filenames){
        closeConnectionDueToError(socket, "error during malloc\n");
        return -1;
    }

    memcpy(filenames, filename_old, filename_old_len);
    memcpy(filenames + filename_old_len, filename_new, filename_new_len);

    ret = sendEncryptedData(filenames, filename_old_len+filename_new_len, socket, false, 0, 0, true);
    free(filenames);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return -1;
    }
    else if(ret == -2) {
        return 0;
    }

    return 0;
}

void list(int socket){
    int rand_len = 8;
    unsigned char* rand = (unsigned char*) malloc(rand_len);
    if(!rand){
        closeConnectionDueToError(socket, "error during malloc\n");
        return;
    }
    RAND_poll();
    int ret = RAND_bytes((unsigned char*)&rand[0], rand_len);
    if(ret!=1){closeConnectionDueToError(socket, "error, RAND bytes failed\n"); return;}

    const char str_op[] = "LIST";
    unsigned char* info_buffer = (unsigned char*) malloc(REQUEST_LEN);
    if(!info_buffer){
        free(rand);
        closeConnectionDueToError(socket, "error during malloc\n");
        return;
    }

    memcpy(info_buffer, str_op, strlen(str_op));
    memcpy(info_buffer + strlen(str_op), rand, rand_len);
    free(rand);

    ret = sendEncryptedData(info_buffer, REQUEST_LEN, socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return;
    }else if(ret==-2){
        return;
    }

    int tag_len = 16;
    int iv_len = 16;
    unsigned char* cipher_list_len = (unsigned char*) malloc(sizeof(int));
    if (!cipher_list_len) {
        closeConnectionDueToError(socket, "Error with malloc");
        return;
    }
    ret = rcvEncrypted(cipher_list_len, sizeof(int), socket);
    if (ret==-1) {
        free(cipher_list_len);
        closeConnectionDueToError(socket, "Error during rcvEncrypted");
        return;
    }

    int list_len = ntohl(*(unsigned int*)(cipher_list_len));
    free(cipher_list_len);

    unsigned char* list = (unsigned char*)malloc(list_len+1);
    if (!list) {
        closeConnectionDueToError(socket, "Error with malloc");
        return;
    }

    ret = rcvEncrypted(list, list_len, socket);
    if (ret==-1) {
        free(cipher_list_len);
        free(list);
        closeConnectionDueToError(socket, "Error during rcvEncrypted");
        return;
    }
    list[list_len]='\0';
    printf("[+] List received, your drive contains the following files :\n%s", list);
    cout << "\n";

    free(list);

}

int authenticate(int socket) {

    EVP_PKEY* dh_params = NULL;
    EVP_PKEY_CTX* pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(pctx, &dh_params);

    //Genero la mia chiave privata e la mia chiave pubblica
    EVP_PKEY *my_dhkey = NULL;
    if(1 != EVP_PKEY_keygen_init(pctx)) 
        handleErrorsInAuthenticate(socket);
    if(1 != EVP_PKEY_keygen(pctx, &my_dhkey)) 
        handleErrorsInAuthenticate(socket);
    EVP_PKEY_CTX_free(pctx);

    //Converto la chiave pubblica in stringa e la invio al server
    BIO * key_bio = BIO_new(BIO_s_mem());
    if (key_bio == NULL)
        handleErrorsInAuthenticate(socket);
    if(1 != PEM_write_bio_PUBKEY(key_bio, my_dhkey))
        handleErrorsInAuthenticate(socket);
    int dhpkey_len = BIO_get_mem_data(key_bio, NULL);
    unsigned char* my_dhpkey_buffer = (unsigned char*)malloc(dhpkey_len);
    if(!my_dhpkey_buffer)
        handleErrorsInAuthenticate(socket);
    if(0 >= BIO_read(key_bio, my_dhpkey_buffer, dhpkey_len))
        handleErrorsInAuthenticate(socket);
    BIO_free(key_bio);

    int ret = send(socket, my_dhpkey_buffer, dhpkey_len, 0);

    printf("[+] M1 sent...\n");

    int len = 0;
    unsigned char* info_len_buffer = (unsigned char*)malloc(4 * sizeof(unsigned int));
    if(!info_len_buffer)
        handleErrorsInAuthenticate(socket);
    /*while( len < 4 * sizeof(unsigned int) ) {
        len += recv(socket, info_len_buffer + len, 4 * sizeof(unsigned int), 0);
        if (ret <= 0) {
            handleErrorsInAuthenticate(socket);
        }
    }*/

    ret = recv(socket, info_len_buffer + len, 4 * sizeof(unsigned int), MSG_WAITALL);
    if (ret <= 0) {
        handleErrorsInAuthenticate(socket);
    }

    int key_len, cert_len, signature_len, iv_len;

    key_len = ntohl(*(unsigned int*)(info_len_buffer));
    cert_len = ntohl(*(unsigned int*)(info_len_buffer + sizeof(unsigned int)));
    signature_len = ntohl(*(unsigned int*)(info_len_buffer + 2*sizeof(unsigned int)));
    iv_len = ntohl(*(unsigned int*)(info_len_buffer + 3*sizeof(unsigned int)));

    free(info_len_buffer);
    

    if ((unsigned int)cert_len > UINT32_MAX - (unsigned int) signature_len ||
        (unsigned int)signature_len > UINT32_MAX - (unsigned int) key_len ||
        (unsigned int)cert_len > UINT32_MAX - (unsigned int) signature_len - (unsigned int)key_len ||
        (unsigned int)iv_len > UINT32_MAX - (unsigned int) signature_len - (unsigned int) key_len||
        (unsigned int)cert_len > UINT32_MAX - (unsigned int) signature_len - (unsigned int) key_len - (unsigned int)iv_len)
        handleErrorsInAuthenticate(socket);

    len = 0;
    unsigned char* buffer = (unsigned char*)malloc(key_len + cert_len + signature_len + iv_len);
    if(!buffer)
        handleErrorsInAuthenticate(socket);
    

    ret = recv(socket, buffer + len, key_len + signature_len + cert_len + iv_len, MSG_WAITALL);
    if(ret <= 0) {
        handleErrorsInAuthenticate(socket);
    }
    
    unsigned char* server_pkey_buffer = (unsigned char*)malloc(key_len);
    if(!server_pkey_buffer)
        handleErrorsInAuthenticate(socket);
    memcpy(server_pkey_buffer, buffer, key_len);

    unsigned char* cert_buffer = (unsigned char*)malloc(cert_len);
    if(!cert_buffer)
        handleErrorsInAuthenticate(socket);
    memcpy(cert_buffer, buffer + key_len, cert_len);

    unsigned char* server_signature_buffer = (unsigned char*)malloc(signature_len);
    if(!server_signature_buffer)
        handleErrorsInAuthenticate(socket);
    memcpy(server_signature_buffer, buffer + key_len + cert_len, signature_len);

    unsigned char* iv_buffer = (unsigned char*)malloc(iv_len);
    if(!iv_buffer)
        handleErrorsInAuthenticate(socket);
    memcpy(iv_buffer, buffer + key_len + cert_len + signature_len, iv_len);

    free(buffer);

    printf("[+] M2 received...\n");

    printf("[+] Checking certificate and signature..\n");
    EVP_PKEY* server_longterm_pubkey = EVP_PKEY_new();
    server_longterm_pubkey = checkServerCert(cert_buffer, cert_len, socket);

    //Converto la chiave da stringa e EVP_PKEY
    BIO* user_bio = BIO_new(BIO_s_mem());
    if (user_bio == NULL)
        handleErrorsInAuthenticate(socket);
    EVP_PKEY* server_pkey = NULL;
    if(0 >= BIO_write(user_bio, server_pkey_buffer, key_len))
        handleErrorsInAuthenticate(socket);
    server_pkey = PEM_read_bio_PUBKEY(user_bio, NULL, NULL, NULL);
    BIO_free(user_bio);
    
    //Genero il segreto condiviso, da cui ottengo la chiave
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *shared_key;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);
    if (!derive_ctx) 
        handleErrorsInAuthenticate(socket);
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) 
        handleErrorsInAuthenticate(socket);

    if (EVP_PKEY_derive_set_peer(derive_ctx, server_pkey) <= 0) 
        handleErrorsInAuthenticate(socket);
        
    EVP_PKEY_derive(derive_ctx, NULL, &skeylen);
    shared_key = (unsigned char*)(malloc(int(skeylen)));
    if (!shared_key) 
        handleErrorsInAuthenticate(socket);
    if (EVP_PKEY_derive(derive_ctx, shared_key, &skeylen) <= 0) 
        handleErrorsInAuthenticate(socket);

    EVP_PKEY_CTX_free(derive_ctx);
    //Calcolo chiavi di sessione
    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* hctx;

    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if(!digest)
        handleErrorsInAuthenticate(socket);

    hctx = EVP_MD_CTX_new();

    if (EVP_DigestInit(hctx, EVP_sha256()) <= 0)
        handleErrorsInAuthenticate(socket);
    if (EVP_DigestUpdate(hctx, (unsigned char*)shared_key, sizeof(shared_key)) <= 0)
        handleErrorsInAuthenticate(socket);
    if (EVP_DigestFinal(hctx, digest, &digestlen) <= 0)
        handleErrorsInAuthenticate(socket);

    EVP_MD_CTX_free(hctx);
    free(shared_key);

    checkEncryptedSignature(server_longterm_pubkey, digest, server_pkey_buffer, my_dhpkey_buffer, server_signature_buffer, key_len, dhpkey_len, signature_len, iv_buffer, iv_len, socket);

    //Creo il messaggio M3 e lo invio, concludendo l'autenticazione
    cout << "[+] Sending M3...\n";

    //-------------------------------GenerateEncryptedSignature---------------------------------

    unsigned char * control_value = (unsigned char*)malloc(dhpkey_len + key_len);
    if(!control_value)
        handleErrorsInAuthenticate(socket);
    memcpy(control_value, server_pkey_buffer, key_len);
    memcpy(control_value + key_len, my_dhpkey_buffer, dhpkey_len);
    
    free(my_dhpkey_buffer);
    free(server_pkey_buffer);

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    iv_len = EVP_CIPHER_iv_length(cipher);

    unsigned char* iv = (unsigned char*) malloc(iv_len);
    if(!iv)
        handleErrorsInAuthenticate(socket);
    RAND_poll();
    ret = RAND_bytes((unsigned char*)&iv[0], iv_len);
    if(ret!=1){cerr<<"Error: RAND_bytes failed\n"; handleErrorsInAuthenticate(socket);}
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(my_priv_key));
    if(!signature)
        handleErrorsInAuthenticate(socket);

    const EVP_MD* md = EVP_sha256();

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){cerr << "Error: malloc returned NULL"; handleErrorsInAuthenticate(socket);}

    ret = EVP_SignInit(md_ctx, md);
    if(ret==0){cerr << "Error: EVP_SignInit returned " << ret << "\n"; handleErrorsInAuthenticate(socket);}

    ret = EVP_SignUpdate(md_ctx, control_value, key_len + dhpkey_len);
    if(ret==0){cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; handleErrorsInAuthenticate(socket);}
    int sgnt_size;

    ret = EVP_SignFinal(md_ctx, signature, (unsigned int*)&sgnt_size, my_priv_key);
    if(ret==0){cerr << "Error: EVP_SignFinal returned " << ret << "\n"; handleErrorsInAuthenticate(socket);}

    EVP_MD_CTX_free(md_ctx);

    int block_size = EVP_CIPHER_block_size(cipher);

    if(sgnt_size > INT_MAX - block_size){cerr<<"Error: integer overflow\n"; handleErrorsInAuthenticate(socket);}
    signature_len = sgnt_size + block_size;
    unsigned char* cipher_signature = (unsigned char*) malloc (signature_len);
    if(!cipher_signature)
        handleErrorsInAuthenticate(socket);
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){cerr<<"Error: EVP_CIPHER_CTX_new returned NULL\n"; handleErrorsInAuthenticate(socket);}

    ret = EVP_EncryptInit(ctx, cipher, digest, iv);
    if(ret != 1){cerr<<"Error: EncryptInit \n"; handleErrorsInAuthenticate(socket);}

    int update_len = 0;
    int total_len = 0;

    ret = EVP_EncryptUpdate(ctx, cipher_signature, &update_len, signature, sgnt_size);
    if(ret != 1){cerr<<"Error: EncryptUpdate \n"; handleErrorsInAuthenticate(socket);}
    total_len += update_len;

    ret = EVP_EncryptFinal(ctx, cipher_signature + total_len, &update_len);
    if(ret != 1){cerr<<"Error: EncryptFinal \n"; handleErrorsInAuthenticate(socket);}
    total_len += update_len;

    EVP_CIPHER_CTX_free(ctx);
    free(signature);
    signature_len = total_len;
    //----------------------------------------------------------------

    int block_size_usr = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    int username_size = sizeof(username);
    int enc_buffer_size = username_size + block_size_usr;
    unsigned char* encrypted_username = (unsigned char*) malloc(enc_buffer_size);
    if(!encrypted_username)
        handleErrorsInAuthenticate(socket);
    int iv_len_username = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    int encrypted_key_len = EVP_PKEY_size(server_longterm_pubkey);
    unsigned char *iv_usr = (unsigned char*)malloc(iv_len_username);
    if(!iv_usr)
        handleErrorsInAuthenticate(socket);
    unsigned char *encrypted_key = (unsigned char*)malloc(encrypted_key_len);
    if(!encrypted_key)
        handleErrorsInAuthenticate(socket);
    int encrypted_username_len = generateEncryptedUsername(username, encrypted_username, server_longterm_pubkey, iv_usr, encrypted_key, socket);

    unsigned char* info_len_buf = (unsigned char*)malloc(5 * sizeof(unsigned int));
    if(!info_len_buf)
        handleErrorsInAuthenticate(socket);

    sprintf((char*)info_len_buf, "%d %d %d %d %d", signature_len, iv_len, encrypted_username_len, iv_len_username, encrypted_key_len);
    
    unsigned int net_signature_len = htonl(signature_len);
    unsigned int net_iv_len = htonl(iv_len);
    unsigned int net_username_len = htonl(encrypted_username_len);
    unsigned int net_iv_usr_len = htonl(iv_len_username);
    unsigned int net_key_len = htonl(encrypted_key_len);

    memcpy(info_len_buf, (unsigned char*)&net_signature_len, sizeof(unsigned int));
    memcpy(info_len_buf + sizeof(unsigned int), (unsigned char*)&net_iv_len, sizeof(unsigned int));
    memcpy(info_len_buf + 2*sizeof(unsigned int), (unsigned char*)&net_username_len, sizeof(unsigned int));
    memcpy(info_len_buf + 3*sizeof(unsigned int), (unsigned char*)&net_iv_usr_len, sizeof(unsigned int));
    memcpy(info_len_buf + 4*sizeof(unsigned int), (unsigned char*)&net_key_len, sizeof(unsigned int));

    ret = send(socket, info_len_buf, 5 * sizeof(unsigned int), 0);
    if (ret == -1) {
        handleErrorsInAuthenticate(socket);
    }
    free(info_len_buf);

    unsigned char* m3_buf = (unsigned char*)malloc(signature_len + iv_len + encrypted_username_len + iv_len_username + encrypted_key_len);
    if(!m3_buf)
        handleErrorsInAuthenticate(socket);
    memcpy(m3_buf, cipher_signature, signature_len);
    free(cipher_signature);
    memcpy(m3_buf + signature_len, iv, iv_len);
    free(iv);
    memcpy(m3_buf + signature_len + iv_len, encrypted_username, encrypted_username_len);
    free(encrypted_username);
    memcpy(m3_buf + signature_len + iv_len + encrypted_username_len, iv_usr, iv_len_username);
    free(iv_usr);
    memcpy(m3_buf + signature_len + iv_len + encrypted_username_len + iv_len_username, encrypted_key, encrypted_key_len);
    free(encrypted_key);
    send(socket, m3_buf, signature_len + iv_len + encrypted_username_len + iv_len_username + encrypted_key_len, 0);
    free(m3_buf);

    cout << "[+] Authentication completed ..\n" ;

    unsigned char* k1, *k2;
    k1 = (unsigned char*)malloc(digestlen/2);
    if(!k1)
        handleErrorsInAuthenticate(socket);
    mempcpy(k1, digest, digestlen/2);
    k2 = (unsigned char*)malloc(digestlen/2);
    if(!k2)
        handleErrorsInAuthenticate(socket);
    memcpy(k2, digest + digestlen/2, digestlen/2);

    serverData = new CommunicationData;
    if(!serverData)
        handleErrorsInAuthenticate(socket);
    serverData->counter = 0;
    serverData->sessionKey[0] = k1;
    serverData->sessionKey[1] = k2;
    serverData->fileDescriptor = socket;
    serverData->index = 0;

    //last
    EVP_PKEY_free(server_longterm_pubkey);
    EVP_PKEY_free(my_dhkey);
    free(digest);
    free(control_value);
    EVP_PKEY_free(server_pkey);
    free(iv_buffer);
    free(server_signature_buffer);
    free(cert_buffer);
    EVP_PKEY_free(dh_params);
    return 0;
}

void initialize() {
    my_priv_key = EVP_PKEY_new();
    printf("[+] Insert your Username... (max 90 chars)\n");
    //Leggi da tastiera
    username = (unsigned char*)malloc(91);
    //it's 90 because my directory path is 
    //home/alessio/DriveProject/Client/$username/$filename
    //and since we want to limit the filename to 128 bytes
    //and the path to 256, doing the math we get approximately 90 bytes
    if (!username)
        handleErrors();

    string username_holder;
    while (true) {
        cin >> username_holder;

        static char okchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_";
        
        if (username_holder.find_first_not_of(okchars) != std::string::npos) {
            continue;
        }
        int len = (90 > (unsigned int)(username_holder.length()) ? (unsigned int)(username_holder.length()) : 90);
        memcpy(username, username_holder.c_str(), len);
        if (len == 90) 
            username[90] = '\0';
        break;
    }
    unsigned char* filename = (unsigned char*)malloc(strlen((char*)username) + 12);
    if (!filename) 
        handleErrors();
    strcat((char*)filename, (char*)username);
    strcat((char*)filename, (char*)"_privkey.pem");
    FILE* file = fopen((char*)filename, "r");
    if (!file)
        handleErrors();
    my_priv_key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if (!my_priv_key)
        handleErrors();
    fclose(file);
    free(filename);
}

int deleteFile(unsigned char* filename, int socket){
    string new_name((char*)filename);
    const char okchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- àòèéù";
    if (new_name.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Invalid new filename!...\n";
        return -1;
    }
    int ret;

    int filename_old_len = strlen((char*)filename);
    const char str_op[] = "DELE";
    unsigned char* info_buffer = (unsigned char*) malloc(REQUEST_LEN);
    if(!info_buffer){
        closeConnectionDueToError(socket, "error during malloc\n");
        return -1;
    }

    RAND_poll();
    ret = RAND_bytes(info_buffer, REQUEST_LEN);
    if (ret <= 0) {
        free(info_buffer);
        closeConnectionDueToError(socket, "Error generating message");
        return -1;
    }

    unsigned int htonl_len_old = htonl(filename_old_len);
    memcpy(info_buffer, str_op, strlen(str_op));
    memcpy(info_buffer + strlen(str_op), (unsigned char*)&htonl_len_old, sizeof(int));

    ret = sendEncryptedData(info_buffer, REQUEST_LEN, socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return -1;
    }
    else if(ret == -2) {
        return 0;
    }

    ret = sendEncryptedData(filename, filename_old_len, socket, false, 0, 0, true);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return -1;
    }
    else if(ret == -2) {
        return 0;
    }

    return 0;

}

int download(unsigned char* filename, unsigned char* new_filename, int socket) {
    string new_name((char*)new_filename);
    const char okchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- àòèéù";
    if (new_name.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Invalid filename!...\n";
        return -1;
    }

    string name((char*)filename);
    if (name.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Invalid filename!...\n";
        return -1;
    }

    int ret;

    file_to_download_name = new_filename;
    file_to_download = fopen((char*)new_filename, "wx");
    if (!file_to_download) {
        cout << "[-] The filename chosen is already defined in our current directory!...\n";
        return -1;
    }
    
    int filename_len = strlen((char*)filename);
    const char str_op[] = "DOWN";
    unsigned char* info_buffer = (unsigned char*) malloc(REQUEST_LEN);
    if(!info_buffer){
        closeConnectionDueToError(socket, "error during malloc\n");
    }

    RAND_poll();
    ret = RAND_bytes(info_buffer, REQUEST_LEN);
    if (ret <= 0) {
        fclose(file_to_download);
        remove((char*)new_filename);
        free(info_buffer);
        closeConnectionDueToError(socket, "Error generating message");
        return -1;
    }

    unsigned int htonl_len = htonl(filename_len);
    memcpy(info_buffer, str_op, strlen(str_op));
    memcpy(info_buffer + strlen(str_op), (unsigned char*)&htonl_len, sizeof(int));

    //Send operation code + length of filename
    ret = sendEncryptedData(info_buffer, REQUEST_LEN, socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        fclose(file_to_download);
        remove((char*)new_filename);
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
    }
    else if(ret == -2) {
        return 0;
    }
    
    //Send filename and waits for status code!!!
    ret=sendEncryptedData(filename, filename_len, socket, false, 0, 0, true);
    if(ret==-1) {
        fclose(file_to_download);
        remove((char*)new_filename);
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
    }
    else if(ret == -2) {
        return 0;
    }

    unsigned char* block_info = (unsigned char*)malloc(2*sizeof(unsigned int));
    if (!block_info) {
        fclose(file_to_download);
        remove((char*)new_filename);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    
    ret = rcvEncrypted(block_info, 2*sizeof(unsigned int), socket);
    if (ret == -1) {
        fclose(file_to_download);
        remove((char*)new_filename);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    unsigned int n_blocks = ntohl(*(unsigned int*)(block_info));
    unsigned int last_block_size = ntohl(*(unsigned int*)(block_info + sizeof(unsigned int)));

    free(block_info);

    if (n_blocks - 1 > UINT_MAX / BLOCK_SIZE ||
        (n_blocks - 1) * BLOCK_SIZE > UINT_MAX - (last_block_size == 0 ? BLOCK_SIZE : last_block_size) ||
        (n_blocks - 1) * BLOCK_SIZE + (last_block_size == 0 ? BLOCK_SIZE : last_block_size) > 4000000000) {
            //Since server can only store a file of less 4GB
            //If he receives a file bigger than that it mean
            //That somebody has modified the message, so we close the session
            fclose(file_to_download);
            remove((char*)new_filename);
            closeConnectionDueToError(socket, "error, file too big...");
            return -1;
    }

    int size = BLOCK_SIZE;

    int n = n_blocks/10 + 1;
    cout << "[+] Loading: ";
    fflush(stdout);
    unsigned char* data = (unsigned char*)malloc(size + 1);
    for (int i = 0; i < n_blocks; ++i) {
        if(i%n==0){
            cout << "*";
            fflush(stdout);
        }
        if (i == n_blocks - 1 && last_block_size != 0) {
            cout << endl;
            size = last_block_size;
            free(data);
            data = (unsigned char*)malloc(size + 1);
        }
        
        ret = rcvEncrypted(data, size, socket);
        data[size] = '\0';
        if (ret == -1) {
            fclose(file_to_download);
            remove((char*)new_filename);
            free(data);
            closeConnectionDueToError(socket, "Error during data reception");
            return -1;
        }
        if(ret==-1){
            fclose(file_to_download);
            remove((char*)new_filename);
            free(data);
            return -1;
        }
        fprintf(file_to_download, "%s", data);
    }

    free(data);
    fclose(file_to_download);
    file_to_download = NULL;
    file_to_download_name = NULL;

    unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
    if(!status_msg){
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    memcpy(status_msg, "OKAY", STATUS_SIZE);

    ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
    free(status_msg);
    if (ret == -1) {
        closeConnectionDueToError(socket, "Error sending status");
        return -1;
    }
    cout << "[+] File stored correctly...\n";

    return 0;

}

void logout(int socket) {
    int rand_len = 8;
    unsigned char* rand = (unsigned char*) malloc(rand_len);
    if(!rand){
        closeConnectionDueToError(socket, "error during malloc\n");
        return;
    }
    RAND_poll();
    int ret = RAND_bytes((unsigned char*)&rand[0], rand_len);
    if(ret!=1){
        closeConnectionDueToError(socket, "error, RAND bytes failed\n");
    }

    const char str_op[] = "LOGO";
    unsigned char* info_buffer = (unsigned char*) malloc(REQUEST_LEN);
    if(!info_buffer){
        free(rand);
        closeConnectionDueToError(socket, "error during malloc\n");
    }

    memcpy(info_buffer, str_op, strlen(str_op));
    memcpy(info_buffer + strlen(str_op), rand, rand_len);
    free(rand);

    ret = sendEncryptedData(info_buffer, REQUEST_LEN, socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return;
    }
    close(socket);
    EVP_PKEY_free(my_priv_key);
    if (serverData != NULL) {
        free(serverData->sessionKey[0]);
        free(serverData->sessionKey[1]);
        free(serverData);
    }
    exit(0);
}

int main() {
    //VARIABLE DECLARATION
    //-----------------------
    int ret;
    int my_socket;
    struct sockaddr_in server_socket;

    unsigned char* input_request;
    unsigned char* p;

    input_request = (unsigned char*)malloc(9);

    //SOCKET GENERATION & REQUEST
    //-----------------------
    my_socket = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_socket, 0, sizeof(server_socket));
    server_socket.sin_family = AF_INET;
    server_socket.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_socket.sin_addr);

    ret = connect(my_socket, (struct sockaddr*)&server_socket, (socklen_t) sizeof(server_socket));
    if (ret < 0) {
        perror("Could not connect to the server");
        handleErrors();
    }
    //-----------------------
    
    initialize();
    socket_holder = my_socket;
    signal(SIGINT, ctrlC_handler);

    ret = authenticate(my_socket);
    if (ret == -1) {
        handleErrors();
    }

    //WORKING PHASE 
    //-----------------------
    scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline

    for(;;) {
        cout << "[+] List of possible operations: \n";
        cout << "\t upload: \t upload a new file on drive\n";
        cout << "\t rename: \t rename a file\n";
        cout << "\t delete: \t delete a file from drive\n";
        cout << "\t list: \t\t show the list of files on drive\n";
        cout << "\t download: \t download a new file from drive\n";
        cout << "\t logout: \t logout\n";

        fgets((char *)input_request, 9, stdin);
        p = (unsigned char*)strchr((char*)input_request, '\n');
        if(p != NULL){ 
            *p = '\0';
        } else {
            scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
        }

        if(strncmp((char*)input_request, "upload", 6) == 0) {
            cout << "[+] Upload request initialized...\n";
            cout << "[*] Which file you want to upload? (not more than 128 chars)...";
            unsigned char* filename = (unsigned char*)malloc(129);
            if(!filename) {
                handleErrors();
            }
            fgets((char*)filename, 128, stdin);
            p = (unsigned char*)strchr((char*)filename, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }
            cout << "\n";
            cout << "[*] With what name you want to save it on drive?...";
            unsigned char* new_name = (unsigned char*)malloc(129);
            if(!new_name) {
                handleErrors();
            }
            fgets((char*)new_name, 128, stdin);
            p = (unsigned char*)strchr((char*)new_name, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }
            cout << "\n";
            new_name[128] = filename[128] = '\0';
            cout << new_name << endl;
            upload(filename, new_name, my_socket);
            free(filename);
            free(new_name);
        }
        else if(strncmp((char*)input_request, "delete", 6) == 0) {
            cout << "[+] Delete request initialized...\n";
            cout << "[] Which file you want to delete? (not more than 128 chars)...";
            unsigned char* filename = (unsigned char*)malloc(129);
            if(!filename) {
                handleErrors();
            }
            fgets((char*)filename, 128, stdin);
            p = (unsigned char*)strchr((char*)filename, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }

            filename[128] = '\0';
            cout << "\n";
            cout << "[] Are you sure you want to delete it? [Y/n]...\n";
            char confirm;
            cin >> confirm;
            cout << "\n";
            if(confirm == 'Y'){
                deleteFile(filename, my_socket);
            }else if(confirm=='n'){
                cout << "[+] Delete request canceled\n";
            }else{
                cout << "[-] Invalid input\n";
            }

            scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            free(filename);
        }
        else if(strncmp((char*)input_request, "rename", 6) == 0) {
            cout << "[+] Rename request initialized...\n";
            cout << "[*] Which file you want to rename? (not more than 128 chars)...";
            unsigned char* filename_old = (unsigned char*)malloc(129);
            if(!filename_old) {
                handleErrors();
            }
            fgets((char*)filename_old, 128, stdin);
            p = (unsigned char*)strchr((char*)filename_old, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }
            cout << "\n";
            cout << "[*] How do you want to rename it?(max 128 chars) ...";
            unsigned char* new_name = (unsigned char*)malloc(129);
            if(!new_name) {
                handleErrors();
            }
            fgets((char*)new_name, 128, stdin);
            p = (unsigned char*)strchr((char*)new_name, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }
            cout << "\n";
            new_name[128] = filename_old[128] = '\0';
            renameFile(filename_old, new_name, my_socket);
            free(filename_old);
            free(new_name);
            
        }
        else if(strncmp((char*)input_request, "list", 4) == 0) {
            cout << "[+] List request initialized...\n";
            list(my_socket);
        }
        else if(strncmp((char*)input_request, "download", 8) == 0) {
            cout << "[+] Download request initialized...\n";
            cout << "[*] Which file you want to download? (not more than 128 chars)...";
            unsigned char* filename = (unsigned char*)malloc(129);
            if(!filename) {
                handleErrors();
            }
            fgets((char*)filename, 128, stdin);
            p = (unsigned char*)strchr((char*)filename, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }
            cout << "\n";
            cout << "[*] With what name you want to save it here?...";
            unsigned char* new_name = (unsigned char*)malloc(129);
            if(!new_name) {
                handleErrors();
            }
            fgets((char*)new_name, 128, stdin);
            p = (unsigned char*)strchr((char*)new_name, '\n');
            if(p != NULL){ 
                *p = '\0';
            } else {
                scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
            }
            cout << "\n";
            new_name[128] = filename[128] = '\0';
            cout << new_name << endl;
            download(filename, new_name, my_socket);
            free(filename);
            free(new_name);
        }
        else if(strncmp((char*)input_request, "logout", 6) == 0) {
            cout << "[+] Logout request initialized...\n";
            logout(my_socket);
        }

        cout << "\n[+]-----------------------------[+]\n";

    }
    //-----------------------

}