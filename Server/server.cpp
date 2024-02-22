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
#include <iterator>
#include <map>
#include <dirent.h>

using namespace std;


#define PORT        5000
#define BUF_LEN     1000000
#define REQUEST_LEN 12
#define BLOCK_SIZE  4000000
#define STATUS_SIZE 4

//This is used to handle upload operation in order to delete the file
//being uploaded when we do Ctrl+C
FILE* file_to_upload;
unsigned char* file_to_upload_name;
int socket_holder;

struct CommunicationData {
    unsigned char* sessionKey[2];
    unsigned int counter;
    unsigned char* username;
    int index;
};

//map<int, CommunicationData> communicationList;
CommunicationData* clientData;
EVP_PKEY* my_priv_key;

void ctrlC_handler(int sig){
    if(file_to_upload!=NULL){
        fclose(file_to_upload);
        remove((char*)file_to_upload_name);
        //free(file_to_upload_name);
    }
    //We define the handler after the initialise so my_priv_key is certainly set
    EVP_PKEY_free(my_priv_key);
    if(clientData!=NULL){
        free(clientData->sessionKey[0]);
        free(clientData->sessionKey[1]);
        free(clientData->username);
        free(clientData);
    }
    close(socket_holder);
    exit(1);
}

void handleErrors() {
    printf("[-] There was an error...\n");
    EVP_PKEY_free(my_priv_key);
    if (clientData != NULL) {
        free(clientData->sessionKey[0]);
        free(clientData->sessionKey[1]);
        free(clientData->username);
        free(clientData);
    }
    exit(1);
}

void handleErrorsInAuthentication(int socket) {
    close(socket);
    printf("[-] Error during authentication...\n");
    EVP_PKEY_free(my_priv_key);
    if (clientData != NULL) {
        free(clientData->sessionKey[0]);
        free(clientData->sessionKey[1]);
        free(clientData->username);
        free(clientData);
    }
    exit(1);
}

void closeConnectionDueToError(int socket, const char* error) {
    
    close(socket);
    if(clientData != NULL){
        cout << "[-] Close connection with user "<< clientData->username << endl;
        printf("[-] %s... : %s\n", error, clientData->username);
    }else{
        cout << "[-] Close connection" << endl;
        printf("[-] %s...\n", error);
    }
    EVP_PKEY_free(my_priv_key);
    if (clientData != NULL) {
        free(clientData->sessionKey[0]);
        free(clientData->sessionKey[1]);
        free(clientData->username);
        free(clientData);
    }
    exit(1);
}

int checkFilename(unsigned char* filename, int filename_len, unsigned char* username, unsigned char* complete_filename) {

    memcpy(complete_filename, "UserDir/", 8);
    memcpy(complete_filename + 8, username, strlen((char*)username));
    complete_filename[strlen((char*)username) + 8] = '/';
    memcpy(complete_filename + 9 + strlen((char*)username), filename, filename_len);

    string name((char*)filename);
    const char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_ àòèéù";
    if (name.find_first_not_of(ok_chars) != std::string::npos) {
        cout << "[-] Invalid filename!...\n";
        return -1;
    }

    return 0;
}

int gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *aad, int aad_len,
                unsigned char *tag,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
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
        //cout << "RET: " << ret << endl;
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

    if (clientData->counter == UINT_MAX) {
        //cout << "Increment index" << endl;
        if(clientData->index == 1) {
            cout << "[-] Connection timed out" << endl;
            return -1;
        }
        clientData->index = 1;
        clientData->counter = 0;
        return 0;
    }
    clientData->counter++;
    return 0;
}

int rcvEncrypted (unsigned char *plaintext, int ciphertext_len, int socket){

    int tag_len = 16;

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_gcm());

    int buffer_len = ciphertext_len + tag_len + iv_len;
    unsigned char* buffer = (unsigned char*)malloc(buffer_len);
    if(!buffer){
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    int len = 0;
    int ret=0;

    ret = recv(socket, buffer, buffer_len, MSG_WAITALL);
    if(ret<=0){
        free(buffer);
        closeConnectionDueToError(socket, "Error during receive");
        return -1;
    }

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    if(!ciphertext){
        free(buffer);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    memcpy(ciphertext, buffer, ciphertext_len);

    unsigned char* tag = (unsigned char*)malloc(tag_len);
    if(!tag){
        free(buffer);
        free(ciphertext);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    memcpy(tag, buffer + ciphertext_len, tag_len);

    unsigned char* iv = (unsigned char*)malloc(iv_len);
    if(!iv){
        free(buffer);
        free(ciphertext);
        free(tag);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    memcpy(iv, buffer + ciphertext_len + tag_len, iv_len);

    unsigned char* key = clientData->sessionKey[clientData->index];

    unsigned char* counter_str = (unsigned char*) malloc(sizeof(int));
    if(!counter_str){
        free(buffer);
        free(ciphertext);
        free(tag);
        free(iv);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    unsigned int counter = htonl(clientData->counter);
    memcpy(counter_str, (unsigned char*)&counter, sizeof(int));

    int plaintext_length = gcm_decrypt(ciphertext, ciphertext_len, counter_str, sizeof(int), tag, key, iv, iv_len, plaintext);
    if(plaintext_length==-1){
        free(buffer);
        free(ciphertext);
        free(counter_str);
        free(iv);
        free(tag);
        closeConnectionDueToError(socket, "Error during decryption");
        return -1;
    }

    free(iv);
    free(tag);
    free(ciphertext);
    free(counter_str);
    free(buffer);


    ret = incrementCounter(socket);
    if(ret==-1){
        return -1;
    }

    return plaintext_length;

}

int sendEncryptedData(const unsigned char* plaintext, int plaintext_len, int socket, bool send_size, unsigned int n_blocks, unsigned int last_block_size, bool wait_status) { 

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
        key = clientData->sessionKey[clientData->index];
        unsigned int net_counter = htonl(clientData->counter);
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

        ret = incrementCounter(socket);
        if (ret == -1) {
            free(ciphertext);
            free(iv);
            free(counter);
            free(tag);
            return -1;
        }

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
            closeConnectionDueToError(socket, "Error sending the message");
            return -1;
        }
    }
    unsigned int net_counter = htonl(clientData->counter);
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

    key = clientData->sessionKey[clientData->index];

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


    if (ret == -1) {
        free(ciphertext);
        free(iv);
        free(counter);
        free(tag);
        return -1;
    }

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
    if(ret==-1)
        return -1;

    if (!wait_status) {
        return 0;
    }

    //Riassocia le key (se è cambiata), ricevi il messaggio di stato e comportati
    //di conseguenza, errori in cifratura, chiudi, altrimenti riparti
    key = clientData->sessionKey[clientData->index];

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
        //This one will never be received by the server, it's here for portability
        //reasons only
        free(status_buffer);
        return -1;
    }
    else if(strncmp((char*)status_buffer, "COPY", 4) == 0) {
        //This one will never be received by the server, it's here for portability
        //reasons only
        free(status_buffer);
        return -1;
    }
    else if(strncmp((char*)status_buffer, "FILE", 4) == 0) {
        //This one will never be received by the server, it's here for portability
        //reasons only
        free(status_buffer);
        return -1;
    }

    free(status_buffer);
    return 0;
}

int clientListRequest(int socket){
    DIR* dir;

    struct dirent *fileStruct;
    struct dirent *fileStructName;
    
    char* nameDir = (char*) malloc(strlen((char*)clientData->username) + 9);
    if(!nameDir){
        closeConnectionDueToError(socket, "error during malloc\n");
        return -1;
    }
    memcpy(nameDir, "UserDir/", 8);
    memcpy(nameDir + 8, (char*)clientData->username, strlen((char*)clientData->username));
    nameDir[strlen((char*)clientData->username) + 9] = '\0';
    
    dir = opendir(nameDir);
    if(!dir){
        free(nameDir);
        closeConnectionDueToError(socket, "error opening the list\n");
        return -1;
    }
    
    int len = 0;
    fileStruct = readdir(dir);
    int num_files = 0;
    while(fileStruct!=NULL){
        if(strncmp(".", fileStruct->d_name, 1)==0 || strncmp("..", fileStruct->d_name, 2)==0){
            fileStruct = readdir(dir);
        }else{
            len += strlen(fileStruct->d_name);
            num_files++;
            fileStruct = readdir(dir);
        }
    }

    closedir(dir);

    unsigned char* info_buffer = (unsigned char*)malloc(sizeof(int));
    if(!info_buffer){
        free(nameDir);
        closeConnectionDueToError(socket, "error during malloc\n");
        return -1;
    }

    unsigned int htonl_len = htonl(len+num_files);
    memcpy(info_buffer, (unsigned char*)&htonl_len, sizeof(int));

    int ret = sendEncryptedData(info_buffer, sizeof(int), socket, false, 0, 0, false);
    free(info_buffer);
    if(ret==-1){
        free(nameDir);
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return -1;
    }

    unsigned char* list = (unsigned char*) malloc(len + num_files);
    if(!list){
        free(nameDir);
        closeConnectionDueToError(socket, "error during malloc\n");
        return -1;
    }
    memset(list, 0, len+num_files);

    dir = opendir(nameDir);
    free(nameDir);
    if(!dir){
        free(list);
        closeConnectionDueToError(socket, "error opening the list\n");
        return -1;
    }
    
    fileStructName = readdir(dir);
    num_files = 0;
    int prev_len = 0;
    while(fileStructName!=NULL){
        if(strncmp(".", fileStructName->d_name, 1)==0 || strncmp("..", fileStructName->d_name, 2)==0){
            fileStructName = readdir(dir);
        }else{
            memcpy(list + prev_len + num_files, fileStructName->d_name, strlen(fileStructName->d_name));
            prev_len += strlen(fileStructName->d_name);
            list[prev_len + num_files]=  '\n';
            num_files ++;
            fileStructName = readdir(dir);
        }
    }

    closedir(dir);

    ret = sendEncryptedData(list, len + num_files, socket, false, 0, 0, false);
    free(list);
    if(ret==-1){
        closeConnectionDueToError(socket, "error during sendEncryptedData\n");
        return -1;
    }

    cout << "[+] List sent correctly" << endl;

    return 0;
}

EVP_PKEY* readPublicKey(unsigned char* encr_username, int len, unsigned char* iv_username, unsigned char* encrypted_key, int iv_usr_len, int enc_key_len, unsigned char* username) {
    EVP_PKEY* user_pkey = EVP_PKEY_new();
    if (!user_pkey) {
        return NULL;
    }

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        EVP_PKEY_free(user_pkey);
        return NULL;
    }

    int ret = EVP_OpenInit(ctx, cipher, encrypted_key, enc_key_len, iv_username, my_priv_key);
    if(ret==0){
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(user_pkey);
        return NULL;
    }
    int nd = 0;
    int ndtot = 0;

    ret = EVP_OpenUpdate(ctx, username, &nd, encr_username, len);
    if(ret==0){
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(user_pkey);
        return NULL;
    }
    ndtot += nd;

    ret = EVP_OpenFinal(ctx, username + ndtot, &nd);
    if(ret == 0 ){
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(user_pkey);
        return NULL;
    }
    ndtot += nd;
    int clear_size = ndtot;

    EVP_CIPHER_CTX_free(ctx);

    string username_holder((char*)username);

    static char okchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_";
    
    if (username_holder.find_first_not_of(okchars) != std::string::npos) {
        cout << "[-] Username with invalid characters!...\n";
        EVP_PKEY_free(user_pkey);
        return NULL;
    }
    username[len] = '\0';
    unsigned char* filename = (unsigned char*)malloc(153);
    if(!filename){
        EVP_PKEY_free(user_pkey);
        return NULL;
    }
    memset(filename, '\0', 153);
    strcat((char*)filename, (char*)"UserKeys/keys/");
    //Since we only admit letters and digits, there is no way in which you can
    //cross the filesystem
    strcat((char*)filename, (char*)username);
    strcat((char*)filename, (char*)"_pubkey.pem");
    
    FILE* file = fopen((char*)filename, "r");
    
    if (!file) {
        EVP_PKEY_free(user_pkey);
        free(filename);
        return NULL;
    }
        
    user_pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);

    if (!user_pkey){
        EVP_PKEY_free(user_pkey);
        free(filename);
        return NULL;
    }
    fclose(file);
    free(filename);

    return user_pkey;
}

int checkEncryptedSignature(EVP_PKEY* longterm_public_key, unsigned char* session_key, unsigned char* server_dhpkey, unsigned char* client_dhpkey, unsigned char* cipher_signature, int server_dhlenght, int client_dhlenght, int signature_len, unsigned char* iv, int iv_len){
    int ret; // used for return values

    //Create and initialise the context

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ 
        return -1;
    }
    ret = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), session_key, iv);
    if(ret != 1){
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0; // total decrypted bytes

    unsigned char* signature = (unsigned char*)malloc(signature_len);
    if(!signature) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ret = EVP_DecryptUpdate(ctx, signature, &update_len, cipher_signature, signature_len);
    if(ret != 1){
        EVP_CIPHER_CTX_free(ctx);
        free(signature);
        return -1;
    }
    total_len += update_len;
    
    ret = EVP_DecryptFinal(ctx, signature + total_len, &update_len);
    if(ret <= 0){
        EVP_CIPHER_CTX_free(ctx);
        free(signature);
        return -1;
    }
    
    total_len += update_len;
    int clear_size = total_len;

    // delete the context from memory:
    EVP_CIPHER_CTX_free(ctx);
    unsigned char* buf = (unsigned char *) malloc(server_dhlenght + client_dhlenght);
    if (!buf) {
        free(signature);
        return -1;
    }
    int buf_lenght = server_dhlenght + client_dhlenght;
    memcpy(buf, server_dhpkey, server_dhlenght);
    memcpy(buf + server_dhlenght, client_dhpkey, client_dhlenght);


    EVP_MD_CTX *ctx_sign = EVP_MD_CTX_new();
    if (!ctx_sign) {
        free(buf);
        free(signature);
        return -1;
    }
    ret = EVP_VerifyInit(ctx_sign, EVP_sha256());
    if(ret == 0){
        free(buf);
        EVP_MD_CTX_free(ctx_sign);
        free(signature);
        return -1;
    }
    
    ret = EVP_VerifyUpdate(ctx_sign, buf, buf_lenght);
    if(ret == 0){
        free(buf);
        EVP_MD_CTX_free(ctx_sign);
        free(signature);
        return -1;
    }
    
    ret = EVP_VerifyFinal(ctx_sign, signature, clear_size, longterm_public_key);
    if(ret == -1){ 
        free(buf);
        EVP_MD_CTX_free(ctx_sign);
        free(signature);
        return -1;
    }
    else if(ret == 0){
        cout << "[-] Invalid signature!...\n";
        free(buf);
        EVP_MD_CTX_free(ctx_sign);
        free(signature);
        return -1;
    }
    cout << "[*] Correct signature..\n";
    free(buf);
    free(signature);
    EVP_MD_CTX_free(ctx_sign);
    return 0;
}

int authenticate (int user_fd, int sock_len) {

    EVP_PKEY* dh_params = NULL;
    EVP_PKEY_CTX* pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        handleErrorsInAuthentication(user_fd);
        return -1;
    }
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    if (EVP_PKEY_paramgen(pctx, &dh_params) <= 0) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    //Genero la mia chiave privata e la mia chiave pubblica
    EVP_PKEY *my_dhkey = NULL;
    if(1 != EVP_PKEY_keygen_init(pctx)) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if(1 != EVP_PKEY_keygen(pctx, &my_dhkey)) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(my_dhkey);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    //Leggo la chiave pubblica dell'utente
    BIO* user_bio = BIO_new(BIO_s_mem());
    if (user_bio == NULL) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        return -1;
    }
    EVP_PKEY* user_pkey = NULL;
    unsigned char* pkey_buffer = (unsigned char*)malloc(256);
    if (!pkey_buffer) {
        BIO_free(user_bio);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        return -1;
    }

    int client_key_len = recv(user_fd, (void*)pkey_buffer, 256, 0);
    
    if (client_key_len <= 0) {
        BIO_free(user_bio);
        free(pkey_buffer);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        return -1;
    }
    pkey_buffer[client_key_len] = '\0';
    if(0 >= BIO_write(user_bio, pkey_buffer, client_key_len)){
        BIO_free(user_bio);
        free(pkey_buffer);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        return -1;
    }
    user_pkey = PEM_read_bio_PUBKEY(user_bio, NULL, NULL, NULL);
    BIO_free(user_bio);
    printf("[+] M1 received...\n");

    //Genero il segreto condiviso, da cui ottengo la chiave
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *shared_key;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);
    if (!derive_ctx) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        EVP_PKEY_free(user_pkey);
        return -1;
    }
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        EVP_PKEY_free(user_pkey);
        return -1;
    }
    if (EVP_PKEY_derive_set_peer(derive_ctx, user_pkey) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        EVP_PKEY_free(user_pkey);
        return -1;
    }
    if (EVP_PKEY_derive(derive_ctx, NULL, &skeylen) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        EVP_PKEY_free(user_pkey);
        return -1;
    }
    shared_key = (unsigned char*)(malloc(int(skeylen)));
    if (!shared_key) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        EVP_PKEY_CTX_free(derive_ctx);
        free(pkey_buffer);
        EVP_PKEY_free(user_pkey);
        return -1;
    }
    if (EVP_PKEY_derive(derive_ctx, shared_key, &skeylen) <= 0) {
        EVP_PKEY_CTX_free(derive_ctx);
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        EVP_PKEY_free(user_pkey);
        free(shared_key);
        return -1;
    }
    EVP_PKEY_free(user_pkey);
    EVP_PKEY_CTX_free(derive_ctx);

    //Calcolo chiavi di sessione
    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* hctx;

    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if (!digest) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(shared_key);
        return -1;
    }

    hctx = EVP_MD_CTX_new();
    if (!hctx) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(shared_key);
        free(digest);
        return -1;
    }

    if (EVP_DigestInit(hctx, EVP_sha256()) <= 0) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(shared_key);
        free(digest);
        EVP_MD_CTX_free(hctx);
        return -1;
    }
    if (EVP_DigestUpdate(hctx, (unsigned char*)shared_key, sizeof(shared_key)) <= 0) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(shared_key);
        free(digest);
        EVP_MD_CTX_free(hctx);
        return -1;
    }
    if (EVP_DigestFinal(hctx, digest, &digestlen) <= 0) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(shared_key);
        free(digest);
        EVP_MD_CTX_free(hctx);
        return -1;
    }

    EVP_MD_CTX_free(hctx);
    free(shared_key);

    printf("[+] Session keys obtained...\n");

    //Invio chiave pubblica, certificato e firma
    unsigned char* my_cert;
    unsigned char* cipher_signature;
    unsigned char* my_dhpkey_buffer;
    unsigned char* iv;

    BIO * key_bio = BIO_new(BIO_s_mem());
    if (key_bio == NULL) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(digest);
        return -1;
    }
    if(0 >= PEM_write_bio_PUBKEY(key_bio, my_dhkey)) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(digest);
        BIO_free(key_bio);
        return -1;
    }
    int dhpkey_len = BIO_get_mem_data(key_bio, NULL);
    my_dhpkey_buffer = (unsigned char*)malloc(dhpkey_len);
    if(!my_dhpkey_buffer) {
        handleErrorsInAuthentication(user_fd);
        BIO_free(key_bio);
        EVP_PKEY_free(my_dhkey);
        free(pkey_buffer);
        free(digest);
        return -1;
    }
    if(0 >= BIO_read(key_bio, my_dhpkey_buffer, dhpkey_len)) {
        handleErrorsInAuthentication(user_fd);
        EVP_PKEY_free(my_dhkey);
        BIO_free(key_bio);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        return -1;
    }
    BIO_free(key_bio);
    EVP_PKEY_free(my_dhkey);


    unsigned char * control_value = (unsigned char*)malloc(dhpkey_len + client_key_len);
    if (!control_value) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        return -1;
    }
    memcpy(control_value, my_dhpkey_buffer, dhpkey_len);
    memcpy(control_value + dhpkey_len, pkey_buffer, client_key_len);

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);

    iv = (unsigned char*) malloc(iv_len);
    if (!iv) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv);
        return -1;
    }
    RAND_poll();
    int ret = RAND_bytes((unsigned char*)&iv[0], iv_len);
    if(ret!=1){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv);
        return -1;
    }

    //-------------------------------GenerateEncryptedSignature---------------------------------
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(my_priv_key));
    if (!signature) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv); free(signature);
        return -1;
    }

    const EVP_MD* md = EVP_sha256();

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv); free(signature);
        return -1;
    }

    ret = EVP_SignInit(md_ctx, md);
    if(ret==0){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv); free(signature);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    ret = EVP_SignUpdate(md_ctx, control_value, client_key_len + dhpkey_len);
    if(ret==0){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv); free(signature);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    int sgnt_size;

    ret = EVP_SignFinal(md_ctx, signature, (unsigned int*)&sgnt_size, my_priv_key);
    if(ret==0){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(control_value);
        free(iv); free(signature);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    free(control_value);
    EVP_MD_CTX_free(md_ctx);

    int block_size = EVP_CIPHER_block_size(cipher);

    if(sgnt_size > INT_MAX - block_size){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(iv); free(signature);
        return -1;
    }
    int signature_len = sgnt_size + block_size;
    cipher_signature = (unsigned char*) malloc (signature_len);
    if(!cipher_signature){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(iv); free(signature);
        return -1;
    }

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(signature);
        return -1;
    }

    ret = EVP_EncryptInit(ctx, cipher, digest, iv);
    if(ret != 1){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(signature);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int update_len = 0;
    int total_len = 0;

    ret = EVP_EncryptUpdate(ctx, cipher_signature, &update_len, signature, sgnt_size);
    if(ret != 1){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(signature);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += update_len;

    ret = EVP_EncryptFinal(ctx, cipher_signature + total_len, &update_len);
    if(ret != 1){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(signature);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += update_len;

    EVP_CIPHER_CTX_free(ctx);
    free(signature);
    signature_len = total_len;
    //----------------------------------------------------------------

    //Leggi il certificato del server, crea il messaggio M2 e invialo

    FILE* certFile = fopen("Server_cert.pem", "r");
    if (!certFile) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv);
        return -1;
    }
    X509* certX509 = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(certFile);
    if(certX509==NULL){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv);
        return -1;
    }

    BIO* certBIO = BIO_new(BIO_s_mem());
    if(PEM_write_bio_X509(certBIO, certX509) <= 0){
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv);
        return -1;
    }

    int cert_len = BIO_get_mem_data(certBIO, NULL);

    my_cert = (unsigned char* ) malloc(cert_len);
    if (!my_cert) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); BIO_free(certBIO);
        return -1;
    }
    if(BIO_read(certBIO, my_cert, cert_len) <= 0) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); BIO_free(certBIO);
        free(my_cert);
        return -1;
    }
    BIO_free(certBIO);

    unsigned char* info_lenght_buffer = (unsigned char*)malloc(4 * sizeof(unsigned int));
    if (!info_lenght_buffer) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(my_cert);
        return -1;
    }
    
    unsigned int net_dhpkey_len, net_cert_len, net_signature_len, net_iv_len;
    net_dhpkey_len = htonl(dhpkey_len);
    net_cert_len = htonl(cert_len);
    net_signature_len = htonl(signature_len);
    net_iv_len = htonl(iv_len);
    memcpy(info_lenght_buffer, (unsigned char*)&net_dhpkey_len, sizeof(unsigned int));
    memcpy(info_lenght_buffer + sizeof(unsigned int), (unsigned char*)&net_cert_len, sizeof(unsigned int));
    memcpy(info_lenght_buffer + 2*sizeof(unsigned int), (unsigned char*)&net_signature_len, sizeof(unsigned int));
    memcpy(info_lenght_buffer + 3*sizeof(unsigned int), (unsigned char*)&net_iv_len, sizeof(unsigned int));

    printf("[+] Sending M2...\n");
    int ret_value = send(user_fd, info_lenght_buffer, sizeof(unsigned int) * 4, 0);
    if (ret_value < 0) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(my_cert);
        return -1;
    }
    free(info_lenght_buffer);

    if ((unsigned int)cert_len > UINT32_MAX - (unsigned int) signature_len ||
        (unsigned int)signature_len > UINT32_MAX - (unsigned int) dhpkey_len ||
        (unsigned int)cert_len > UINT32_MAX - (unsigned int) signature_len - (unsigned int)dhpkey_len ||
        (unsigned int)iv_len > UINT32_MAX - (unsigned int) signature_len - (unsigned int) dhpkey_len||
        (unsigned int)cert_len > UINT32_MAX - (unsigned int) signature_len - (unsigned int) dhpkey_len - (unsigned int)iv_len) {
            handleErrorsInAuthentication(user_fd);
            free(pkey_buffer);
            free(my_dhpkey_buffer);
            free(digest); free(cipher_signature);
            free(iv); free(my_cert);
            return -1;
        }

    unsigned char* m2_buffer = (unsigned char *)malloc(dhpkey_len + cert_len + signature_len + iv_len);
    if (!m2_buffer) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest); free(cipher_signature);
        free(iv); free(my_cert);
        return -1;
    }

    memcpy(m2_buffer, my_dhpkey_buffer, dhpkey_len);
    memcpy(m2_buffer + dhpkey_len, my_cert, cert_len);
    free(my_cert);
    memcpy(m2_buffer + dhpkey_len + cert_len, cipher_signature, signature_len);
    free(cipher_signature);
    memcpy(m2_buffer + dhpkey_len + cert_len + signature_len, iv, iv_len);
    free(iv);
    ret_value = send(user_fd, m2_buffer, dhpkey_len + cert_len + signature_len + iv_len, 0);
    if (ret_value < 0) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(m2_buffer);
        return -1;
    }
    free(m2_buffer);
    
    printf("[+] Sent M2...\n");
    //Leggo ultimo messaggio
    //Aggiungo elemento in lista

    int len = 0;
    unsigned char* info_buffer = (unsigned char*) malloc(5 * sizeof(unsigned int));
    if (!info_buffer) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        return -1;
    }
    ret_value = 0;

    ret_value = recv(user_fd, info_buffer + len, 5 * sizeof(unsigned int), MSG_WAITALL);
    if (ret_value <= 0) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(info_buffer);
        return -1;
    }

    int client_signature_len, client_iv_len, client_encr_name_len, client_iv_usr_len, client_encr_key_len;
    
    client_signature_len = ntohl(*(unsigned int*)(info_buffer));
    client_iv_len = ntohl(*(unsigned int*)(info_buffer + sizeof(unsigned int)));
    client_encr_name_len = ntohl(*(unsigned int*)(info_buffer + 2*sizeof(unsigned int)));
    client_iv_usr_len = ntohl(*(unsigned int*)(info_buffer + 3*sizeof(unsigned int)));
    client_encr_key_len = ntohl(*(unsigned int*)(info_buffer + 4*sizeof(unsigned int)));
    
    free(info_buffer);
    if ((unsigned int)client_signature_len > UINT32_MAX - (unsigned int) client_iv_len ||
        (unsigned int)client_encr_name_len > UINT32_MAX - (unsigned int) client_signature_len - (unsigned int)client_iv_len || 
        (unsigned int)client_iv_usr_len > UINT32_MAX - (unsigned int) client_signature_len - (unsigned int)client_iv_len - (unsigned int)client_encr_name_len ||
        (unsigned int)client_encr_key_len > UINT32_MAX - (unsigned int) client_signature_len - (unsigned int)client_iv_len - (unsigned int)client_encr_name_len - (unsigned int)client_iv_usr_len) {
            handleErrorsInAuthentication(user_fd);
            free(pkey_buffer);
            free(my_dhpkey_buffer);
            free(digest);
            return -1;
        }
        
    unsigned char* client_signature = (unsigned char*)malloc(client_signature_len);
    if(!client_signature) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        return -1;
    }
    unsigned char* client_iv = (unsigned char*) malloc(client_iv_len);
    if(!client_iv) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature);
        return -1;
    }
    unsigned char* client_encr_name = (unsigned char*)malloc(client_encr_name_len);
    if(!client_encr_name) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        return -1;
    }
    unsigned char* client_iv_usr = (unsigned char*)malloc(client_iv_usr_len);
    if(!client_iv_usr) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name);
        return -1;
    }
    unsigned char* client_encr_key = (unsigned char*)malloc(client_encr_key_len);
    if(!client_encr_key) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name); free(client_iv_usr);
        return -1;
    }
    unsigned char* m3_buf = (unsigned char*)malloc(client_signature_len + client_iv_len + client_encr_name_len+ client_iv_usr_len + client_encr_key_len);
    if(!m3_buf) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name); free(client_iv_usr);
        free(client_encr_key);
        return -1;
    }
        
    len = 0;
    ret_value = 0;

    ret_value = recv(user_fd, m3_buf + len, client_signature_len + client_iv_len + client_encr_name_len + client_iv_usr_len + client_encr_key_len, 0);
    if (ret_value <= 0) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name); free(client_iv_usr);
        free(client_encr_key); free(m3_buf);
        return -1;
    }

    memcpy((char*)client_signature, (char*)m3_buf, client_signature_len);
    memcpy((char*)client_iv, (char*)m3_buf + client_signature_len, client_iv_len);
    memcpy((char*)client_encr_name, (char*)m3_buf + client_signature_len + client_iv_len, client_encr_name_len);
    memcpy((char*)client_iv_usr, (char*)m3_buf + client_signature_len + client_iv_len + client_encr_name_len, client_iv_usr_len);
    memcpy((char*)client_encr_key, (char*)m3_buf + client_signature_len + client_iv_len + client_encr_name_len + client_iv_usr_len, client_encr_key_len);
    free(m3_buf);

    unsigned char* username = (unsigned char*)malloc(client_encr_name_len);
    if (!username) {
        handleErrorsInAuthentication(user_fd);
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name); free(client_iv_usr);
        free(client_encr_key);
        return -1;
    }

    EVP_PKEY* user_pubkey = readPublicKey(client_encr_name, client_encr_name_len, client_iv_usr, client_encr_key, client_iv_len, client_encr_key_len, username);
    if (!user_pubkey) {
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name); free(client_iv_usr);
        free(client_encr_key); free(username);
        return -1;
    }

    ret_value = checkEncryptedSignature(user_pubkey, digest, my_dhpkey_buffer, pkey_buffer, client_signature, dhpkey_len, client_key_len, client_signature_len, client_iv, client_iv_len);
    if (ret_value == -1) {
        free(pkey_buffer);
        free(my_dhpkey_buffer);
        free(digest);
        free(client_signature); free(client_iv);
        free(client_encr_name); free(client_iv_usr);
        free(client_encr_key); free(username);
        return -1;
    }
    free(pkey_buffer);
    free(my_dhpkey_buffer);
    free(client_signature); 
    free(client_iv);
    free(client_encr_name); 
    free(client_iv_usr);
    free(client_encr_key);

    unsigned char* k1, *k2;
    k1 = (unsigned char*)malloc(digestlen/2);
    if(!k1) {
        handleErrorsInAuthentication(user_fd);
        free(digest);
        free(username);
        return -1;
    }
    mempcpy(k1, digest, digestlen/2);
    k2 = (unsigned char*)malloc(digestlen/2);
    if(!k2) {
        handleErrorsInAuthentication(user_fd);
        free(digest);
        free(username);
        return -1;
    }
    memcpy(k2, digest + digestlen/2, digestlen/2);
    free(digest);

    clientData = new CommunicationData;
    if(!clientData) {
        handleErrorsInAuthentication(user_fd);
        free(username);
        return -1;
    }

    cout << "[+] Authentication completed: " << username << "... \n";

    clientData->counter = 0;
    clientData->sessionKey[0] = k1;
    clientData->sessionKey[1] = k2;
    clientData->username = username;
    clientData->index = 0;
    
    return 0;
}

//Read private key
void initialize() {
    my_priv_key = EVP_PKEY_new();
    FILE* file = fopen("Server_privkey.pem", "r");
    my_priv_key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if (!my_priv_key)
        handleErrors();
    fclose(file);
}

int clientUploadRequest(unsigned char* filename, unsigned int filename_len, int socket) {
    unsigned char* complete_filename = (unsigned char*)malloc(filename_len + 9 + strlen((char*)clientData->username) + 1);
    if (!complete_filename) {
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    filename[filename_len] = '\0';
    int ret = checkFilename(filename, filename_len, clientData->username, complete_filename);
    if (ret == -1) {
        //SEND INVALID FILENAME TU USER
        free(complete_filename);
        unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
        if(!status_msg){
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        cout << "[-] Invalid filename!...\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }
    complete_filename[filename_len + 9 + strlen((char*)clientData->username)] = '\0';
    file_to_upload_name = complete_filename;
    file_to_upload = fopen((char*)complete_filename, "wx");
    if (!file_to_upload) {
        //SEND INVALID FILENAME TO USER
        free(complete_filename);
        unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
        if(!status_msg){
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        cout << "[-] File already exists!...\n";
        memcpy(status_msg, "COPY", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }

    unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
    if(!status_msg){
        fclose(file_to_upload);
        remove((char*)complete_filename);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }

    memcpy(status_msg, "OKAY", STATUS_SIZE);

    ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
    free(status_msg);
    if (ret == -1) {
        fclose(file_to_upload);
        remove((char*)complete_filename);
        closeConnectionDueToError(socket, "Error sending status");
        return -1;
    }
    
    unsigned char* block_info = (unsigned char*)malloc(2*sizeof(unsigned int));
    if (!block_info) {
        fclose(file_to_upload);
        remove((char*)complete_filename);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    
    ret = rcvEncrypted(block_info, 2*sizeof(unsigned int), socket);
    if (ret == -1) {
        fclose(file_to_upload);
        remove((char*)complete_filename);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    unsigned int n_blocks = ntohl(*(unsigned int*)(block_info));
    unsigned int last_block_size = ntohl(*(unsigned int*)(block_info + sizeof(unsigned int)));
    free(block_info);

    if (n_blocks - 1 > UINT_MAX / BLOCK_SIZE ||
        (n_blocks - 1) * BLOCK_SIZE > UINT_MAX - (last_block_size == 0 ? BLOCK_SIZE : last_block_size) ||
        (n_blocks - 1) * BLOCK_SIZE + (last_block_size == 0 ? BLOCK_SIZE : last_block_size) > 4000000000) {
            //SEND FILE TOO BIG
            status_msg = (unsigned char*) malloc(STATUS_SIZE);
            if(!status_msg){
                fclose(file_to_upload);
                remove((char*)complete_filename);
                closeConnectionDueToError(socket, "Error during malloc");
                return -1;
            }
            cout << "[-] File too big!\n";
            memcpy(status_msg, "TBIG", STATUS_SIZE);
            ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
            free(status_msg);
            fclose(file_to_upload);
            remove((char*)complete_filename);
            
            if (ret == -1) {
                closeConnectionDueToError(socket, "Error sending status");
                return -1;
            }
            return 0;
    }

    status_msg = (unsigned char*)malloc(STATUS_SIZE);
    if(!status_msg){
        closeConnectionDueToError(socket, "Error during malloc...");
        return -1;
    }

    memcpy(status_msg, "OKAY", STATUS_SIZE);

    ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
    free(status_msg);
    if(ret==-1){
        closeConnectionDueToError(socket, "Error while sending data...");
        return -1;
    }

    int size = BLOCK_SIZE;

    unsigned char* data = (unsigned char*)malloc(size+1);
    for (int i = 0; i < n_blocks; ++i) {
        
        if (i == n_blocks - 1 && last_block_size != 0) {
            size = last_block_size;
            free(data);
            data = (unsigned char*)malloc(size+1);
        }

        ret = rcvEncrypted(data, size, socket);
        data[size]='\0';
        if (ret == -1) {
            fclose(file_to_upload);
            remove((char*)complete_filename);
            free(data);
            closeConnectionDueToError(socket, "Error during data reception");
            return -1;
        }

        if(ret==-1){
            fclose(file_to_upload);
            remove((char*)complete_filename);
            free(data);
            return -1;
        }
        fprintf(file_to_upload, "%s", data);
    }

    free(data);
    fclose(file_to_upload);
    file_to_upload=NULL;
    file_to_upload_name=NULL;
    free(complete_filename);

    status_msg = (unsigned char*) malloc(STATUS_SIZE);
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

int clientRenameRequest(unsigned char* filename_old, int filename_old_len, unsigned char* filename_new, int filename_new_len, int socket){
    
    unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
    if(!status_msg){
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    int ret;
    unsigned char* complete_old_filename = (unsigned char*)malloc(filename_old_len + 9 + strlen((char*)clientData->username));
    if (!complete_old_filename) {
        free(status_msg);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    ret = checkFilename(filename_old, filename_old_len, clientData->username, complete_old_filename);
    
    if (ret == -1) {
        //send invalid filename and restart service
        cout << "[-] Invalid old filename!...\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        free(complete_old_filename);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }

    unsigned char* complete_new_filename = (unsigned char*)malloc(filename_new_len + 9 + strlen((char*)clientData->username));
    if (!complete_new_filename) {
        free(status_msg);
        free(complete_old_filename);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    ret = checkFilename(filename_new, filename_new_len, clientData->username, complete_new_filename);
    
    if (ret == -1) {
        //send invalid filename and restart service
        cout << "[-] Invalid new filename!...\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        free(complete_old_filename);
        free(complete_new_filename);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }

    ret = rename((char*)complete_old_filename, (char*)complete_new_filename);
    if(ret < 0){
        cout << "[-] File doesn't exists\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        free(complete_old_filename);
        free(complete_new_filename);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }
    memcpy(status_msg, "OKAY", STATUS_SIZE);
    ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
    free(status_msg);
    if (ret == -1) {
        free(complete_old_filename);
        free(complete_new_filename);
        closeConnectionDueToError(socket, "Error sending status");
        return -1;
    }
    cout << "[+] File " << complete_old_filename << " renamed into " << complete_new_filename << endl;
    free(complete_old_filename);
    free(complete_new_filename);

    return 0;
}

int clientDeleteRequest(unsigned char* filename, int filename_len, int socket){
    
    unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
    if(!status_msg){
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    int ret;
    unsigned char* complete_filename = (unsigned char*)malloc(filename_len + 9 + strlen((char*)clientData->username));
    if (!complete_filename) {
        free(status_msg);
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    ret = checkFilename(filename, filename_len, clientData->username, complete_filename);
    
    if (ret == -1) {
        //send invalid filename and restart service
        cout << "[-] Invalid old filename!...\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        free(complete_filename);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }

    ret = remove((char*)complete_filename);
    if(ret < 0){
        cout << "[-] File doesn't exists\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        free(complete_filename);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }

    memcpy(status_msg, "OKAY", STATUS_SIZE);
    ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
    free(status_msg);
    if (ret == -1) {
        closeConnectionDueToError(socket, "Error sending status");
        return -1;
    }
    cout << "[+] File " << complete_filename << " deleted"  << endl;
    free(complete_filename);

    return 0;
}

int clientDownloadRequest(unsigned char* filename, unsigned int filename_len, int socket) {
    unsigned char* complete_filename = (unsigned char*)malloc(filename_len + 9 + strlen((char*)clientData->username) + 1);
    if (!complete_filename) {
        closeConnectionDueToError(socket, "Error during malloc");
        return -1;
    }
    filename[filename_len] = '\0';
    int ret = checkFilename(filename, filename_len, clientData->username, complete_filename);
    if (ret == -1) {
        //SEND INVALID FILENAME TU USER
        free(complete_filename);
        unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
        if(!status_msg){
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        cout << "[-] Invalid filename!...\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }
    complete_filename[filename_len + 9 + strlen((char*)clientData->username)] = '\0';
    FILE* file = fopen((char*)complete_filename, "r");
    if (!file) {
        //SEND INVALID FILENAME TO USER
        free(complete_filename);
        unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
        if(!status_msg){
            closeConnectionDueToError(socket, "Error during malloc");
            return -1;
        }
        cout << "[-] File doesn't exists!...\n";
        memcpy(status_msg, "FILE", STATUS_SIZE);
        ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
        free(status_msg);
        if (ret == -1) {
            closeConnectionDueToError(socket, "Error sending status");
            return -1;
        }
        return 0;
    }
    free(complete_filename);

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

    for(int i = 0; i < number_blocks; i++){
        unsigned char* send_buffer;
        if(!multiple && i == number_blocks - 1){
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
                closeConnectionDueToError(socket, "Error while sending data!...\n");
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
                closeConnectionDueToError(socket, "[-] Error while sending data!...\n");
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

void serveClient(int socket) {
    int tag_len = 16;
    int iv_len = 16;
    int cipher_len, ret;
    unsigned char* client_request;
    while(true) {
        cipher_len = REQUEST_LEN;
        client_request = (unsigned char*) malloc(iv_len + tag_len + cipher_len);
        if (!client_request) {
            closeConnectionDueToError(socket, "Error with malloc");
            return;
        }
        ret = rcvEncrypted(client_request, cipher_len, socket);
        if (ret == -1) {
            free(client_request);
            return;
        }

        unsigned char* buffer;

        if (strncmp((char*)client_request, "UPLO", 4) == 0) {
            cout << "\n[+]-----------------------------[+]\n[+] Received request of upload by:" << clientData->username << endl;
            unsigned int filename_lenght = ntohl(*(unsigned int*)(client_request+4));

            if (filename_lenght > 128) {
                //SEND INVALID FILENAME TO CLIENT
                unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
                if(!status_msg){
                    closeConnectionDueToError(socket, "Error during malloc");
                    return;
                }
                cout << "[-] Invalid new filename!...\n";
                memcpy(status_msg, "FILE", STATUS_SIZE);
                ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
                free(status_msg);
                if (ret == -1) {
                    closeConnectionDueToError(socket, "Error sending status");
                    return;
                }
            }
            else {
                free(client_request);
                buffer = (unsigned char*)malloc(filename_lenght);
                if (!buffer) {
                    closeConnectionDueToError(socket, "Error during malloc");
                    return;
                }

                ret = rcvEncrypted(buffer, filename_lenght, socket);
                if(ret==-1){
                    return;
                }

                ret = clientUploadRequest(buffer, filename_lenght, socket);
                if (ret == -1) {
                    return;
                }
                
                free(buffer);
            }
        }
        else if (strncmp((char*)client_request, "DOWN", 4) == 0) {
            cout << "\n[+]-----------------------------[+]\n[+] Received request of download by:" << clientData->username << endl;
            unsigned int filename_lenght = ntohl(*(unsigned int*)(client_request+4));

            if (filename_lenght > 128) {
                //SEND INVALID FILENAME TO CLIENT
                unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
                if(!status_msg){
                    closeConnectionDueToError(socket, "Error during malloc");
                    return;
                }
                cout << "[-] Invalid new filename!...\n";
                memcpy(status_msg, "FILE", STATUS_SIZE);
                ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
                free(status_msg);
                if (ret == -1) {
                    closeConnectionDueToError(socket, "Error sending status");
                    return;
                }
            }
            else {
                free(client_request);
                buffer = (unsigned char*)malloc(filename_lenght);
                if (!buffer) {
                    closeConnectionDueToError(socket, "Error during malloc");
                    return;
                }

                ret = rcvEncrypted(buffer, filename_lenght, socket);
                if(ret==-1){
                    return;
                }

                ret = clientDownloadRequest(buffer, filename_lenght, socket);
                if (ret == -1) {
                    return;
                }
                
                free(buffer);
            }
        }
        else if (strncmp((char*)client_request, "LIST", 4) == 0) {
            cout << "\n[+]-----------------------------[+]\n[+]Received request for list of files by: " << clientData->username << endl;
            free(client_request);
            ret = clientListRequest(socket);
            
            if(ret == -1){
                return;
            }

        }
        else if (strncmp((char*)client_request, "DELE", 4) == 0) {
            cout << "\n[+]-----------------------------[+]\n[+]Received request of delete by: " << clientData->username << endl;
            unsigned int filename_len = ntohl(*(unsigned int*)(client_request+4));

            if (filename_len > 128) {
                //SEND INVALID FILENAME TO CLIENT
                unsigned char* status_msg = (unsigned char*) malloc(STATUS_SIZE);
                if(!status_msg){
                    closeConnectionDueToError(socket, "Error during malloc");
                    return;
                }
                cout << "[-] Invalid new filename!...\n";
                memcpy(status_msg, "FILE", STATUS_SIZE);
                ret = sendEncryptedData(status_msg, STATUS_SIZE, socket, false, 0, 0, false);
                free(status_msg);
                if (ret == -1) {
                    closeConnectionDueToError(socket, "Error sending status");
                    return;
                }
            }
            else {
                free(client_request);
                buffer = (unsigned char*)malloc(filename_len);
                if (!buffer) {
                    cout << "[-] Error during malloc\n";
                    return;
                }

                ret = rcvEncrypted(buffer, filename_len, socket);
                if (ret == -1)
                    return;
                buffer[filename_len]='\0';

                ret = clientDeleteRequest(buffer,  filename_len+1, socket);
                if (ret == -1) {
                    return;
                }
                free(buffer);
            }

        }
        else if (strncmp((char*)client_request, "LOGO", 4) == 0) {
            cout << "\n[+]-----------------------------[+]\n[+] Logout: " << clientData->username << endl;
            close(socket);
            EVP_PKEY_free(my_priv_key);
            if (clientData != NULL) {
                free(clientData->sessionKey[0]);
                free(clientData->sessionKey[1]);
                free(clientData->username);
                free(clientData);
            }
            exit(0);
        }
        else if (strncmp((char*)client_request, "RENA", 4) == 0) {
            cout << "\n[+]-----------------------------[+]\n[+] Received request of renaming by: " << clientData->username << endl;
            unsigned int filename_old_len = ntohl(*(unsigned int*)(client_request+4));
            unsigned int filename_new_len = ntohl(*(unsigned int*)(client_request+8));

            if(filename_old_len > 128 || filename_new_len>128){
                cout << "[-] Filename too long\n";
                return;
            }

            free(client_request);
            buffer = (unsigned char*)malloc(filename_old_len + filename_new_len);
            if (!buffer) {
                cout << "[-] Error during malloc\n";
                return;
            }

            ret = rcvEncrypted(buffer, filename_old_len + filename_new_len, socket);
            if (ret == -1) {
                return;
            }

            unsigned char* filename_old = (unsigned char*) malloc(filename_old_len+1);
            if(!filename_old){
                cout << "[-] Error during malloc\n";
                free(buffer);
                return;
            }
            memcpy(filename_old, buffer, filename_old_len);
            filename_old[filename_old_len]='\0';

            unsigned char* filename_new = (unsigned char*) malloc(filename_new_len+1);
            if(!filename_new){
                cout << "[-] Error during malloc\n";
                free(buffer);
                free(filename_old);
                return;
            }
            memcpy(filename_new, buffer + filename_old_len, filename_new_len);
            free(buffer);
            filename_new[filename_new_len]='\0';

            ret = clientRenameRequest(filename_old,  filename_old_len+1, filename_new, filename_new_len+1, socket);
            free(filename_old);
            free(filename_new);
            if (ret == -1) {
                return;
            }
        }
    }
}

int main() {
    //VARIABLES DECLARATION
    //-----------------------
    int ret;
    int new_client_fd; //fd created when a client has been accepted
    int listener_fd;
    int i; //used for "for" loops
    int sock_len;
    fd_set master; //contains all fds to analize
    fd_set fd_to_read; //used to check if our fd are readable
    int fd_max; //contain the highest fd value
    struct sockaddr_in server_sock, client_sock;
    char *p; //This is used to fine the \n character in a buffer
    //-----------------------

    //SOCKET GENERATION
    //-----------------------
    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int)) < 0)
        cerr << "Couldn't create the socket\n"; 
    memset(&server_sock, 0, sizeof(server_sock));
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(PORT);
    server_sock.sin_addr.s_addr = INADDR_ANY;
    ret = bind(listener_fd, (struct sockaddr*)&server_sock, sizeof(server_sock));
    if (ret < 0) {
        perror("Error during bind");
        exit(1);
    }
    listen(listener_fd, 10);
    //-----------------------

    //FD_SET INITIALIZATION
    //-----------------------
    FD_ZERO(&master);
    FD_ZERO(&fd_to_read);
    FD_SET(0, &master); //this allow me to check if we wrote on stdin
    FD_SET(listener_fd, &master);
    fd_max = listener_fd;
    //-----------------------
    initialize();

    socket_holder = listener_fd;
    signal(SIGINT, ctrlC_handler);
    //MAIN LOOP
    //-----------------------
    while(1) {
        //CHECK FILE DESCRIPTORS
        //-----------------------
        fd_to_read = master;
        ret = select(fd_max + 1, &fd_to_read, NULL, NULL, NULL);
        if (ret < 0) {
            perror("Error during select function");
            handleErrors();
        }

        for (i = 0; i <= fd_max; ++i) {
            if (FD_ISSET(i, &fd_to_read)) {
                //if i is the listener_fd, then
                //i just got a new connection request
                //INSERT NEW CLIENT TO LIST
                //-----------------------
                if (i == listener_fd) {
                    
                    cout << "\n[+]-----------------------------[+]\n[+] New connection request\n";
                    //fflush(stdout);
                    sock_len = sizeof(client_sock);
                    
                    new_client_fd = accept(listener_fd, (struct sockaddr*)&client_sock, (socklen_t*)&sock_len);
                    //FD_SET(new_client_fd, &master);
                    /*if (new_client_fd > fd_max) {
                        fd_max = new_client_fd;
                    }*/

                    int pid = fork();
                    if (pid == 0) {
                        socket_holder = new_client_fd;
                        close(listener_fd);
                        //Authenticate
                        ret = authenticate(new_client_fd, sock_len);

                        if (ret != -1) {
                            serveClient(new_client_fd);
                        }
                        handleErrors();
                    }else{
                        //FD_SET(listener_fd, &master);
                        close(new_client_fd);
                    }
                    

                }
                //-----------------------
                //READ FROM STDIN
                //-----------------------
                else if (i == 0) { 
                    unsigned char* input_request = (unsigned char*) malloc(5);
                    fgets((char *)input_request, 5, stdin);
                    p = strchr((char*)input_request, '\n');
                    if(p != NULL){ 
                        *p = '\0';
                    } else {
                        scanf("%*[^\n]");scanf("%*c"); //clear stdin up to newline
                    }
                    input_request[4] = '\0';
                    if(strncmp((char*)input_request, "exit", 4) == 0) {
                        close(listener_fd);
                        EVP_PKEY_free(my_priv_key);
                        cout << "[-] Cannot accept further requests...\n";
                        ret = 0;
                        int* status;
                        while(ret>=0){
                            ret = wait(status);
                        }
                        exit(0);
                    }
                }
            }
            FD_SET(i, &master);
        }
        //-----------------------

    }
    //-----------------------
    close(listener_fd);
    EVP_PKEY_free(my_priv_key);
    exit(0);
}