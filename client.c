#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#define UDP_PACKAGE_SIZE 78
#define TCP_PACKAGE_SIZE 178

pthread_t aliveThread, commandThread;

char client_cfg_file[] = "client.cfg";
char network_cfg_file[] = "boot.cfg";

char id[7];
char MAC[13];
char NMSId[13];
char NMSUDPport[5];

char sendBuffUDP[UDP_PACKAGE_SIZE]; //Buffer d'enviament UDP
char recvBuffUDP[UDP_PACKAGE_SIZE]; //Buffer de recepció UDP

char sendBuffTCP[TCP_PACKAGE_SIZE]; //Buffer d'enviament TCP
char recvBuffTCP[TCP_PACKAGE_SIZE]; //Buffer de recepció TCP

int udp_sock; // Socket UDP
int tcp_sock = 0; // Socket TCP

int status; // Ens diu el estat del client

bool debug_mode = false;
char debug_str[500];

struct sockaddr_in addr_server_udp, addr_cli_udp;
struct sockaddr_in addr_server_tcp, addr_cli_tcp;

int port_tcp; // Port TCP que farem anar per enviar les comandes i la conf

struct PDU_UDP {
    unsigned char type;
    char id[7];
    char MAC_addr[13];
    char random_num[7];
    char data[50];
};

struct PDU_UDP pdu_udp_recv;
struct PDU_UDP pdu_udp_send;

struct PDU_TCP
{
    unsigned char type;
    char id[7];
    char MAC_addr[13];
    char random_num[7];
    char data[150];
};

struct PDU_TCP pdu_tcp_recv;
struct PDU_TCP pdu_tcp_send;

/*----------------------------*/
struct PDU_UDP registryPDU;
/*----------------------------*/

struct waitingTimes
{
    int t;
    int p;
    int q;
    int u;
    int n;
    int o;
};

struct aliveTimes
{
    int r;
    int s;
};

struct commandTimes
{
    int w;
};

enum registerStatus {
    REGISTER_REQ = 0x00, // Petició de registre
    REGISTER_ACK = 0x02, // Acceptació de registre
    REGISTER_NACK = 0x04, // Deneagació de registre
    REGISTER_REJ = 0x06, // Rebuig de registre
    ERROR = 0x0F // Error del protocol
};

enum clientStatus {
    DISCONNECTED = 0xA0, // Equip desconectat
    WAIT_REG_RESPONSE = 0xA2, // Espera de resposta a la petició de registre
    WAIT_DB_CHECK = 0xA4, // Espera de consulta BB. DD. d’equips autoritzats
    REGISTERED = 0xA6, // Equip registrat, sense intercanvi ALIVE
    SEND_ALIVE = 0xA8 // Equip enviant i rebent paquets de ALIVE
};

enum aliveStatus {
    ALIVE_INF = 0x10, // Enviament d'informació d'alive
    ALIVE_ACK = 0x12, // Confirmació de recepció d'informació d'alive
    ALIVE_NACK = 0x14, // Denegacio de recepció d'informació d'alive
    ALIVE_REJ = 0x16 // Rebuig de recepció d'informació d'alive
};

enum sendFileStatus{
    SEND_FILE = 0x20, // Petició d’enviament d’arxiu de configuració
    SEND_DATA = 0x22, // Bloc de dades de l’arxiu de configuració
    SEND_ACK = 0x24, // Acceptació de la petició d’enviament d’arxiu de configuració
    SEND_NACK = 0x26, // Denegació de la petició d’enviament d’arxiu de configuració
    SEND_REJ = 0x28, // Rebuig de la petició d’enviament d’arxiu de configuració
    SEND_END = 0x2A // Fi de l’enviament de dades de l’arxiu de configuració
};

enum receiveFileStatus{
    GET_FILE = 0x30, // Petició d’obtenció d’arxiu de configuració
    GET_DATA = 0x32, // Bloc de dades de l’arxiu de configuració
    GET_ACK = 0x34, // Acceptació d’obtenció d’arxiu de configuració
    GET_NACK = 0x36, // Denegació d’obtenció d’arxiu de configuració
    GET_REJ = 0x38, // Rebuig d’obtenció d’arxiu de configuració
    GET_END = 0x3A // Fi de l’obtenció de l’arxiu de configuració
};

/*Struct que guarda els temporitzadors de la fase de registre*/
//                                   [t, p, q, u, n, o]
struct waitingTimes registryTimers = {1, 2, 3, 2, 6, 2};


/* Struct que guarda els temporitzadors de la fase alive */
//                              [r, s]
struct aliveTimes aliveTimers = {2, 3};


/*Struct que guarda els temporitzadors de la fase d'enviament de commandes*/
//                                  [w] 
struct commandTimes commandTimers = {3};

time_t start_t, end_t;
double total_t;

void registryProcedure();
void registryRequest();
void registerPhase();
void print_message();
bool isValidPDU();
void send_data();
void get_file();
void debug_log();

double timePassed(){
    double t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
    return t;
}

/*
void pdu_UDP_to_arr(struct PDU_UDP pdu, char buff[]){

    buff[0] = pdu.type;
    strcpy(buff + 1, pdu.id);
    strcpy(buff + 8, pdu.MAC_addr);
    strcpy(buff + 21, pdu.random_num);
    strcpy(buff + 28, pdu.data);
}

void arr_to_pdu_UDP(char buff[], struct PDU_UDP* pdu){

    //strncpy(dest, src + beginIndex, endIndex - beginIndex);

    pdu->type = buff[0];
    strncpy(pdu->id, buff + 1,  8 - 1);
    strncpy(pdu->MAC_addr, buff + 8, 21 - 8);
    strncpy(pdu->random_num, buff + 21, 28 - 21);
    strncpy(pdu->data, buff + 28, 78 - 28);
}

void pdu_TCP_to_arr(struct PDU_TCP pdu, char buff[]){
    //TODO
}

void arr_to_pdu_TCP(char buff[], struct PDU_UDP* pdu){
    //TODO
}
*/

void setupTCP(){

    if(tcp_sock == 0){ // Si el socket no està inicialitzat
        tcp_sock = socket(AF_INET, SOCK_STREAM, 0);

        if(tcp_sock < 0 ){
            perror("No s'ha pogut obrir el socket TCP. \n");
            exit(-1);
        }

        struct hostent *ent;

        ent = gethostbyname(NMSId);

        /*Inicialitzar l'adreça del client*/
        memset(&addr_cli_tcp, 0, sizeof(struct sockaddr_in));
        addr_cli_tcp.sin_family = AF_INET;
        addr_cli_tcp.sin_addr.s_addr = htonl(INADDR_ANY);
        addr_cli_tcp.sin_port = htons(0);

        /*Inicialitzar l'adreça del servidor*/
        memset(&addr_server_tcp, 0, sizeof(struct sockaddr_in));
        addr_server_tcp.sin_family = AF_INET;
        addr_server_tcp.sin_addr.s_addr = ((struct in_addr *)ent->h_addr_list[0])->s_addr;
        addr_server_tcp.sin_port = htons(port_tcp);

        /* Binding */
        if(bind(tcp_sock, (struct sockaddr *) &addr_cli_tcp, sizeof(addr_cli_tcp)) < 0){
            perror("No s'ha pogut fer el binding del socket TCP\n");
            close(tcp_sock);
            exit(-1);
        }

        if(connect(tcp_sock, (struct sockaddr *) &addr_server_tcp, sizeof(addr_server_tcp)) < 0){
            perror("No s'ha pogut connectar amb el servidor\n");
            close(tcp_sock);
            exit(-1);
        }

        debug_log("**** Socket TCP Inicialitzat! ****");
    }
}

char* get_file_size(char* filename) {
    FILE* fp = fopen(filename, "rb"); // Obrim l'arxiu en mode binari

    if (fp == NULL) {
        perror("error al intentar obrir l'arxiu");
        return "Error: unable to open file"; 
    }

    fseek(fp, 0L, SEEK_END); // movem el punter del arxiu al final
    long int size = ftell(fp); // Obtenim la posició actual, que es la mida del arxiu.
    fclose(fp);

    // convert size to string and return it
    char* str = (char*) malloc(50 * sizeof(char)); // assignar memoria per la string
    sprintf(str, "%ld", size); // convert size to string
    return str;
}

void build_TCP_PDU(struct PDU_TCP* pdu, int mnemonic, char buffer[]){

    char data_str[20];

    switch (mnemonic)
    {
    case SEND_FILE:
        //posem els valors corresponents de la pdu
        pdu->type = mnemonic;
        strcpy(pdu->id, id);
        strcpy(pdu->MAC_addr, MAC);
        strcpy(pdu->random_num, registryPDU.random_num);

        memset(data_str, 0, sizeof(data_str)); // Per inicialitzar el string com buit
        strcat(data_str, client_cfg_file); // nom del arxiu de conf local
        strcat(data_str, ","); // separem amb una coma

        char* size_str = get_file_size(client_cfg_file); // guardem en una variable la mida del arxiu de conf

        strcat(data_str, size_str); // mida del arxiu de conf

        free(size_str); // Alliberem la memoria assignada per a client_cfg_file

        strcpy(pdu->data, data_str);

        break;

    case SEND_DATA:
        //posem els valors corresponents de la pdu
        pdu->type = mnemonic;
        strcpy(pdu->id, id);
        strcpy(pdu->MAC_addr, MAC);
        strcpy(pdu->random_num, registryPDU.random_num);

        //enviem linia a linia l'arxiu
        strcpy(pdu->data, buffer);

        break;

    case SEND_END:
        //posem els valors corresponents de la pdu
        pdu->type = mnemonic;
        strcpy(pdu->id, id);
        strcpy(pdu->MAC_addr, MAC);
        strcpy(pdu->random_num, registryPDU.random_num);

        memset(pdu->data, '\0', sizeof(pdu->data)); // No ens especifiquen que hem de posar al camp de dades en aquest cas

        break;

    case GET_FILE:
        //posem els valors corresponents de la pdu
        pdu->type = mnemonic;
        strcpy(pdu->id, id);
        strcpy(pdu->MAC_addr, MAC);
        strcpy(pdu->random_num, registryPDU.random_num);

        strcpy(pdu->data, network_cfg_file);

        break;
    default:
        debug_log("Tipus de paquet TCP no vàlid");
        break;
    }
}

bool handle_tcp_packet(){ // Retorna true si el paquet TCP a tractar es de tipus [SEND_ACK] o [GET_ACK] i tracta cada cas de manera independent

    switch(pdu_tcp_recv.type){
        
        case SEND_ACK:

            //Si la resposta del servidor és un paquet [SEND_ACK] amb els camps de la PDU correctes 
            if(isValidPDU(pdu_tcp_recv, registryPDU)){ 
                
                char filename[10];
                strcat(filename, id);
                strcat(filename, ".cfg");

                //i en el camp data el nom de l’arxiu que es guardarà en el servidor (<id_equip>.cfg)
                if(strcmp(filename, pdu_tcp_recv.data) == 0){
                    //es passarà a enviar l’arxiu de configuració amb paquets [SEND_DATA] (un per línia)
                    debug_log("S'ha rebut un [SEND_ACK] vàlid");
                    send_data(); // un cop rebut el [SEND_ACK] podem començar a enviar l'arxiu linia a linia
                }
            }

            else
            {
                debug_log("S'ha rebut un [SEND_ACK] amb camps de PDU no correctes");
            }

            return true;

            break;
        
        case GET_ACK:

            if(isValidPDU(pdu_tcp_recv, registryPDU)){
                get_file();
            }

            return true;
            break;

        default:

            return false;
            break;
    }

    return false;
}

void get_file(){

    /* Obrim el fitxer */
    FILE *fp = fopen(network_cfg_file, "w");

    if(fp == NULL){
        perror("No es pot obrir el fitxer! ");
        exit(1);
    }

    int num_bytes = 0;
    int activity = 0;

    while (true)
    {
        //Macros que fara anar el select
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(tcp_sock, &read_fds);

        //Inicialitzar el timer per al select
        struct timeval tv;

        tv.tv_sec = commandTimers.w;
        tv.tv_usec = 0;

        activity = select(tcp_sock+1, &read_fds, NULL, NULL, &tv); //Esperem al select com a màxim w

        if(activity == -1){
            perror("\nselect\n");
            exit(-1);
        }

        if(activity == 0){ //salta el timeout
            debug_log("No hi ha hagut comunicació amb el servidor TCP");
            debug_log("Es finalitzarà la conexió TCP");

            close(tcp_sock);
            tcp_sock = 0;

            break;
        }

        else //Hem rebut alguna cosa
        {
                num_bytes = recv(tcp_sock, &pdu_tcp_recv, sizeof(pdu_tcp_recv), 0);

                if(num_bytes < 0){
                    perror("\nError al recv\n");
                    exit(-1);
                }

                if(activity == 0){ //Conexió finalitzada remotament
                    debug_log("No hi ha hagut comunicació amb el servidor TCP");
                    debug_log("Es finalitzarà la conexió TCP");

                    close(tcp_sock);
                    tcp_sock = 0;

                    break;
                }

                sprintf(debug_str, "Rebut: Bytes=%lu, type=%i, nom=%s, mac=%s, random=%s, dades=%s", sizeof(pdu_tcp_recv), pdu_tcp_recv.type, pdu_tcp_recv.id, pdu_tcp_recv.MAC_addr, pdu_tcp_recv.random_num, pdu_tcp_recv.data);
                debug_log(debug_str);

                if(pdu_tcp_recv.type == GET_DATA){
                    if(isValidPDU(pdu_tcp_recv, registryPDU)){
                        fputs(pdu_tcp_recv.data, fp);
                    }
                }

                if(pdu_tcp_recv.type == GET_END){
                    sprintf(debug_str, "Arxiu de configuració rebut: %s", network_cfg_file);
                    debug_log(debug_str);
                    tcp_sock = 0;
                    break;
                }
        }
    }

    fclose(fp);
}

void send_data(){

    /* Obrim el fitxer */
    FILE *fp = fopen(network_cfg_file, "r");

    if(fp == NULL){
        perror("No es pot obrir el fitxer! ");
        exit(1);
    }

    char buffer[150]; // La longitud màxima de la linia es de 150 caracters
    int num_bytes = 0;

    /* Enviem els paquets [SEND_DATA] amb les dades del fitxer */
    while (fgets(buffer, sizeof(buffer), fp) != NULL) //S'executa per cada linia del fitxer
    {
        build_TCP_PDU(&pdu_tcp_send, SEND_DATA, buffer); //Creem el paquet [SEND_DATA]

        num_bytes = send(tcp_sock, &pdu_tcp_send, sizeof(pdu_tcp_send), 0); //Enviem el paquet
        debug_log("S'ha enviat un paquet [SEND_DATA]");

        if(num_bytes < 0){
            perror("\nError al enviar\n");
            exit(-1);
        }

        memset(buffer, '\0', sizeof(buffer));
    }

    /* Finalitzem la transmisió enviant un [SEND_END] */
    build_TCP_PDU(&pdu_tcp_send, SEND_END, NULL);
    debug_log("S'ha enviat un paquet [SEND_END]");
    num_bytes = send(tcp_sock, &pdu_tcp_send, sizeof(pdu_tcp_send), 0);

    if(num_bytes < 0){
        perror("\nError al enviar\n");
        exit(-1);
    }

    debug_log("Arxiu de configuració enviat");

    tcp_sock = 0;
    fclose(fp); //Tanquem el fitxer
}

void send_conf(){
    debug_log("SEND CONF");

    build_TCP_PDU(&pdu_tcp_send, SEND_FILE, NULL); //Crear paquet SEND_FILE
    int num_bytes = send(tcp_sock, &pdu_tcp_send, sizeof(pdu_tcp_send), 0);
    print_message("Enviat paquet [SEND_FILE]");

    if(num_bytes < 0){
        perror("Error al send\n");
        exit(-1);
    }

    num_bytes = 0;
    int activity = 0;

    while (activity == 0)
    {
        //Macros que fara anar el select
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(tcp_sock, &read_fds);

        //Inicialitzar el timer per al select
        struct timeval tv;

        tv.tv_sec = commandTimers.w;
        tv.tv_usec = 0;

        activity = select(tcp_sock+1, &read_fds, NULL, NULL, &tv); //Esperem al select com a màxim w

        if(activity == -1){
            perror("\nselect\n");
            exit(-1);
        }

        if(activity == 0){ //salta el timeout
            debug_log("No hi ha hagut comunicació amb el servidor TCP");
            debug_log("Es finalitzarà la conexió TCP");

            close(tcp_sock);
            tcp_sock = 0;

            break;
        }

        else //Hem rebut alguna cosa
        {
            num_bytes = recv(tcp_sock, &pdu_tcp_recv, sizeof(pdu_tcp_recv), 0);

            if(num_bytes < 0){
                perror("\nError al recv\n");
                exit(-1);
            }

            if(activity == 0){ //Conexió finalitzada remotament
                debug_log("No hi ha hagut comunicació amb el servidor TCP");
                debug_log("Es finalitzarà la conexió TCP");

                close(tcp_sock);
                tcp_sock = 0;

                break;
            }

            sprintf(debug_str, "Rebut: Bytes=%lu, type=%i, nom=%s, mac=%s, random=%s, dades=%s", sizeof(pdu_tcp_recv), pdu_tcp_recv.type, pdu_tcp_recv.id, pdu_tcp_recv.MAC_addr, pdu_tcp_recv.random_num, pdu_tcp_recv.data);
            debug_log(debug_str);

            if(!handle_tcp_packet()){ //En cas que la resposta del paquet [SEND_FILE] no sigui un [SEND_ACK]
                //s’informarà del motiu (indicat en el camp data de la PDU) i es finalitzarà la comunicació TCP amb el servidor.
                sprintf(debug_str, "%s", pdu_tcp_recv.data);
                debug_log(debug_str);

                close(tcp_sock);
                tcp_sock = 0;
            }
        }
    }
    
}

void get_conf(){
    debug_log("GET CONF");

    int num_bytes = 0;

    build_TCP_PDU(&pdu_tcp_send, GET_FILE, NULL);
    num_bytes = send(tcp_sock, &pdu_tcp_send, sizeof(pdu_tcp_send), 0);
    debug_log("Paquet [GET_FILE] enviat");

    if(num_bytes < 0){
        perror("\nError al send\n");
        exit(-1);
    }

    num_bytes = 0;
    int activity = 0;

    while (activity == 0)
    {
        //Macros que fara anar el select
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(tcp_sock, &read_fds);

        //Inicialitzar el timer per al select
        struct timeval tv;

        tv.tv_sec = commandTimers.w;
        tv.tv_usec = 0;

        activity = select(tcp_sock+1, &read_fds, NULL, NULL, &tv); //Esperem al select com a màxim w

        if(activity == -1){
            perror("\nselect\n");
            exit(-1);
        }

        if(activity == 0){ //salta el timeout
            debug_log("No hi ha hagut comunicació amb el servidor TCP");
            debug_log("Es finalitzarà la conexió TCP");

            close(tcp_sock);
            tcp_sock = 0;

            break;
        }

        else //Hem rebut alguna cosa
        {
            num_bytes = recv(tcp_sock, &pdu_tcp_recv, sizeof(pdu_tcp_recv), 0);

            if(num_bytes < 0){
                perror("\nError al recv\n");
                exit(-1);
            }

            if(activity == 0){ //Conexió finalitzada remotament
                debug_log("No hi ha hagut comunicació amb el servidor TCP");
                debug_log("Es finalitzarà la conexió TCP");

                close(tcp_sock);
                tcp_sock = 0;

                break;
            }

            sprintf(debug_str, "Rebut: Bytes=%lu, type=%i, nom=%s, mac=%s, random=%s, dades=%s", sizeof(pdu_tcp_recv), pdu_tcp_recv.type, pdu_tcp_recv.id, pdu_tcp_recv.MAC_addr, pdu_tcp_recv.random_num, pdu_tcp_recv.data);
            debug_log(debug_str);

            if(!handle_tcp_packet()){ //En cas que la resposta del paquet [GET_FILE] no sigui un [GET_ACK]
                //s’informarà del motiu (indicat en el camp data de la PDU) i es finalitzarà la comunicació TCP amb el servidor.
                sprintf(debug_str, "%s", pdu_tcp_recv.data);
                debug_log(debug_str);

                close(tcp_sock);
                tcp_sock = 0;
            }
        }
    }
    
}

void commandProcessing(char command[]){
    if(strcmp(command, "quit") == 0){
        pthread_detach(aliveThread);
        pthread_cancel(aliveThread);
        pthread_detach(commandThread);
        close(udp_sock);
        close(tcp_sock);
        debug_log("Threads acabats i sockets tancats");
        exit(1);
        pthread_exit(NULL);
    }

    else if (strcmp(command, "send-cfg") == 0)
    {
        setupTCP();
        send_conf();
    }

    else if (strcmp(command, "get-cfg") == 0)
    {
        setupTCP();
        get_conf();
    }

    else{
        print_message("Commanda invàlida");
        sprintf(debug_str, "---%s---", command);
        debug_log(debug_str);
        //exit(-1);
    }
    
}

void readCommands(){

    char command[9]; //maxim de longitud 9 la commanda
    //memset(command, '\0', sizeof(command)); // Per inicialitzar el string com buit

    while(true){
        scanf("%9s", command);
        commandProcessing(command);

        if(status == DISCONNECTED){
            debug_log("Acabant amb el fil de commandes degut a que s'ha passat al estat [DISCONNECTED]");
            pthread_detach(commandThread);
            pthread_exit(NULL);
        }
    }
}

void *commandPhase(){

    readCommands();
    return NULL;
}

int current_packet = 0;

void *send_ALIVE_INF(){

    // Enviar un paquet ALIVE_INF cada r segons
    while (true)
    {
        debug_log("Enviant paquet: [ALIVE_INF]");
        int a = sendto(udp_sock, &pdu_udp_send, UDP_PACKAGE_SIZE, 0, (struct sockaddr*)&addr_server_udp,sizeof(addr_server_udp));
        if(a<0){
            {
                fprintf(stderr,"Error al sendto\n");
                exit(-2);
            }
        }

        current_packet += 1;
        sprintf(debug_str, "current_packet: %i", current_packet);
        debug_log(debug_str);

        sleep(aliveTimers.r);

        //Si el client no rep confirmació de recepció d’alive a 's' paquets [ALIVE_INF] 
        //consecutius interpretarà que hi ha problemes de comunicació amb el servidor, 
        //passarà a l’estat DISCONNECTED i iniciarà un nou procés de registre.
        if(current_packet >= aliveTimers.s){
            printf(debug_str, "no s'ha rebut confirmació després d'enviar %i paquets consecutius", aliveTimers.s);
            debug_log(debug_str);
            print_message("el client passa al estat: [DISCONNECTED]");
            status = DISCONNECTED;

            current_packet = 0;

            close(tcp_sock);
            tcp_sock = 0;

            pthread_detach(aliveThread);
            pthread_exit(NULL);
        }
    }
    return NULL;
}

bool isMatchPDU(struct PDU_UDP pdu1, struct PDU_UDP pdu2){

    if(strcmp(pdu1.id, pdu2.id) != 0) { return false; }
    if(strcmp(pdu1.MAC_addr, pdu2.MAC_addr) != 0) { return false; }
    if(strcmp(pdu1.random_num, pdu2.random_num) != 0) { return false; }
    //if(strcmp(pdu1.data, pdu2.data) != 0) { return false; } -> EN ELS PAQUETS ALIVE EL CAMP DE DADES HA D'ESTAR BUIT
    return true;

}

bool isValidPDU(struct PDU_TCP pdu1, struct PDU_UDP pdu2){

    if(strcmp(pdu1.id, pdu2.id) != 0) { return false; }
    if(strcmp(pdu1.MAC_addr, pdu2.MAC_addr) != 0) { return false; }
    if(strcmp(pdu1.random_num, pdu2.random_num) != 0) { return false; }
    //if(strcmp(pdu1.data, pdu2.data) != 0) { return false; } -> No cal comparar les dades rebudes
    return true;

}


int num_alive_ack_recieved = 0;

void aliveProcedure(){

    int activity = 0;

    while (activity == 0) // mentres salti el timeout del select (no es rep res)
    {
        //Macros que fara anar el select
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_sock, &read_fds);

        //Inicialitzar el timer per al select
        struct timeval tv;

        tv.tv_sec = aliveTimers.r;
        tv.tv_usec = 0;

        activity = select(udp_sock+1, &read_fds, NULL, NULL, &tv); //Esperem al select com a màxim r

        if(activity == -1){
            // Error occurred
            perror("select() \n");
            exit(-1);
        }

        else if(activity == 0){ //Timeout ocurred
            break;
        }

        else{ //There's activity on the socket

            int a = recvfrom(udp_sock, &pdu_udp_recv, UDP_PACKAGE_SIZE, 0, (struct sockaddr *) 0, (unsigned int *) 0);
            if(a<0)
            {
                fprintf(stderr,"Error al recvfrom\n");
                exit(-2);
            }

            int type = pdu_udp_recv.type;

            if(type == ALIVE_ACK){
                //*en els packets alive el camp de dades ha d'estar buit
                debug_log("rebut [ALIVE_ACK]");

                //struct PDU_UDP aliveRecvPDU;
                //arr_to_pdu_UDP(recvBuffUDP, &aliveRecvPDU);

                // (*) Comprovar que els camps de la PDU corresponen amb les dades obtingudes en la fase de registre
                if(isMatchPDU(registryPDU, pdu_udp_recv)){
                    debug_log("els paquets de la fase de registre i del alive coincideixen");
                    num_alive_ack_recieved += 1;

                    //resetejem el contador de paquets alive_inf consecutius
                    current_packet = 0;

                    //En rebre el primer [ALIVE_ACK] correcte el servidor passarà a l'estat ALIVE
                    if(num_alive_ack_recieved == 1){
                        print_message   ("El client passa al estat [SEND_ALIVE]");
                        status = SEND_ALIVE;
                    }
                }
                else{
                    debug_log("Els paquets de la fase de registre i del alive no coincideixen! No es farà cas del paquet rebut");
                    //No es fara cas del paquet rebut
                }
            }
            
            //La recepció d’un paquet [ALIVE_REJ] en l’estat ALIVE es considerarà com un intent
            //de suplantació d’identitat, el client passarà a l’estat DISCONNECTED i iniciarà un nou
            //procés de registre
            if(type == ALIVE_REJ){
                debug_log("[ALIVE_REJ]: s'interpreta com intent de suplantació d'identitat");
                print_message("\nEl client passa al estat: [DISCONNECTED]");
                status = DISCONNECTED;
                break;
            }


            if(type == ALIVE_NACK){
                //No es tenen en compte, es considera com no haver rebut resposta del servidor
                debug_log("[ALIVE_NACK] rebut");
            }

            /*---------------------------------------------------------------*/
        }
    }

    if(status == DISCONNECTED){
        registerPhase();
    }
    
}

void alivePhase(){

    
    //arr_to_pdu_UDP(recvBuffUDP, &registryPDU);
    memcpy(&registryPDU, &pdu_udp_recv, sizeof(pdu_udp_recv));

    /* Crear i assignar valors de la estructura PDU_UDP */
    pdu_udp_send.type = ALIVE_INF;
    strcpy(pdu_udp_send.random_num, registryPDU.random_num);

    //pdu_UDP_to_arr(pdu_udp, sendBuffUDP);

    //Enviar paquet ALIVE_INF cada r segons
    int threadResult = pthread_create(&aliveThread, NULL, send_ALIVE_INF, NULL);

    if(threadResult != 0){
        perror("Ha fallat el pthread_create");
        exit(-1);
    }

    while (status == SEND_ALIVE || status == REGISTERED)
    {
        aliveProcedure();
    }
}

bool first_registry_request = true;

void registryRequest(){

    /* Crear i assignar valors de la estructura PDU_UDP */
    pdu_udp_send.type = REGISTER_REQ;
    strcpy(pdu_udp_send.id, id);
    strcpy(pdu_udp_send.MAC_addr, MAC);
    //strcpy(pdu_udp.random_num, "000000");
    strcpy(pdu_udp_send.data, "");
    
    //pdu_UDP_to_arr(pdu_udp, sendBuffUDP); // Convertir struct a array que podem enviar

    int a = sendto(udp_sock, &pdu_udp_send, UDP_PACKAGE_SIZE, 0, (struct sockaddr*)&addr_server_udp,sizeof(addr_server_udp));
    if(a<0){
        {
            fprintf(stderr,"Error al sendto\n");
            exit(-2);
        }
    }
    debug_log("S'ha enviat [REGISTER_REQ]");

    if(first_registry_request == true){
        status = WAIT_REG_RESPONSE; // En enviar el primer paquet [REGISTER_REQ] el client passarà a estat WAIT_REG_RESPONSE.
        print_message("El client passa al estat: [WAIT_REG_RESPONSE]");

        first_registry_request = false;
    }
    

}

void registryProcedure(){

    int current_packet = 1;
    int interval = registryTimers.t; // (*) L’interval d’enviament dels primers p paquets és t segons.

    int activity = 0; // guarda l'estat del select

    debug_log("*** INICIANT NOU PROCÉS DE REGISTRE ***");

    while (activity == 0) // mentres salti el timeout del select (no es rep res)
    {
        //Macros que fara anar el select
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_sock, &read_fds);

        //Inicialitzar el timer per al select
        struct timeval tv;

        tv.tv_sec = interval;
        tv.tv_usec = 0;

        activity = select(udp_sock+1, &read_fds, NULL, NULL, &tv);
        

        if (activity == -1) {

            // Error occurred
            perror("select() \n");
            exit(-1);

        } else if (activity == 0) {

            // Timeout occurred
            sprintf(debug_str, "TIMEOUT (seconds: %i)", interval);
            debug_log(debug_str);
            debug_log("es tornarà a enviar la petició de registre");

            //Si no rep resposta del servidor en t segons tornarà a enviar la petició de registre 

            // (*) L’interval d’enviament dels primers p paquets és t segons.
            // --> No cal modificar res

            // (*) Si els paquets enviats es superior a el nombre de p primers paquets
            if(current_packet > registryTimers.p){
                sprintf(debug_str, "el nombre de paquets enviats es superior a p: [%i]", registryTimers.p);
                debug_log(debug_str);
                // Per cada paquet posterior a p l’interval d’enviament s’incrementarà en t segons
                // fins arribar a q * t segons a partir dels quals l’interval d’enviament es mantindrà
                // constant en aquest valor (q * t).

                if(interval < (registryTimers.q * registryTimers.t)){
                    interval += registryTimers.t; //mentres no s'arriba a q * t segons d'interval
                }
            }


            // (*) Si després d’enviar n paquets no s’ha completat el procés de registre, 
            //  s’espera u segons i s’inicia un nou procés de registre.
            if(current_packet > registryTimers.n){ 
                interval = registryTimers.u;
                debug_log("S'iniciarà un nou procés de registre si s'escau");
                break; // -> Per iniciar un nou procés de registre
            }
            
            current_packet += 1;

            registryRequest();


        } else {
            // There is activity on the socket

            int a = recvfrom(udp_sock, &pdu_udp_recv, UDP_PACKAGE_SIZE, 0, (struct sockaddr *) 0, (unsigned int *) 0);
            if(a<0)
            {
                fprintf(stderr,"Error al recvfrom\n");
                exit(-2);
            }

            int type = pdu_udp_recv.type;
            char data[50];
            strncpy(data, pdu_udp_recv.data, sizeof(data));

            if(type == REGISTER_ACK){
                debug_log("S'ha rebut: [REGISTER_ACK]");
                print_message("El client passa al status: [REGISTERED]");

                //Ens guardem el port rebut per a les comunicacions TCP amb el servidor
                //struct PDU_UDP registryPDU;
                //arr_to_pdu_UDP(recvBuffUDP, &registryPDU);
                port_tcp = atoi(pdu_udp_recv.data);

                status = REGISTERED;
            }
            if(type == REGISTER_NACK){
                debug_log("[REGISTER_NACK]: es finalitzarà el procés de registre actual");
                break; // -> Finalitzar el procés de registre actual
            }
            if(type == REGISTER_REJ){
                sprintf(debug_str, "[REGISTER_REJ]: %s", data);
                debug_log(debug_str);
                exit(-1);
            }
            if(type == ALIVE_ACK){
                break;
            }
        }
    }
}

int num_tries = 1;

void registerPhase(){

    first_registry_request = true;

    // Si passats o processos de registre no s’ha finalitzat satisfactòriament el procés, el
    //client finalitzarà indicant que no s’ha pogut contactar amb el servidor.
    while (num_tries <= registryTimers.o && status != REGISTERED)
    {
        sprintf(debug_str, "Registre equip, intent: %i", num_tries);
        debug_log(debug_str);

        registryRequest();
        registryProcedure();
        num_tries += 1;
    }

    if(status == REGISTERED){

        //Crear thread per al tractament de comandes
        int threadResult = pthread_create(&commandThread, NULL, commandPhase, NULL);

        if(threadResult != 0){
            perror("Ha fallat el pthread_create");
            exit(-1);
        }

        alivePhase(); // Mantenir comunicació periodica amb el servidor

        num_tries = 1;
    }
    else
    {
        debug_log("\nNo s'ha pogut conectar amb el servidor! \n");
        exit(-1);
    }
}

void readParameters(int argc, char const *argv[]){

    if(argc <= 1){
        return;
    }

    for (int i = 1; i < argc; i++)
    {
        if(strcmp(argv[i], "-c") == 0){
            i++;
            strcpy(client_cfg_file, argv[i]);
        }

        if(strcmp(argv[i], "-f") == 0){
            i++;
            strcpy(network_cfg_file, argv[i]);
        }

        if(strcmp(argv[i], "-d") == 0){
            //i++;
            debug_mode = true;
            debug_log("Mode debug activat!");
        }
    }
    

    debug_log("Llegits parametres linia de comandes");
}

void debug_log(char *message) {
    if (debug_mode) {
        time_t current_time;
        char timestamp[20];
        struct tm *time_info;

        time(&current_time);
        time_info = localtime(&current_time);

        strftime(timestamp, sizeof(timestamp), "%d-%m-%Y %H:%M:%S", time_info);

        printf("[DEBUG %s] %s\n", timestamp, message);
    }
}


void print_message(char* message) {
    time_t current_time;
    char timestamp[20];
    struct tm *time_info;

    time(&current_time);
    time_info = localtime(&current_time);

    strftime(timestamp, sizeof(timestamp), "%d-%m-%Y %H:%M:%S", time_info);

    printf("[SYSTEM %s] %s\n", timestamp, message);
}


void saveConfig(char filename[]){

    FILE *fp = fopen(filename, "r");

    if(fp == NULL){
        perror("No es pot obrir el fitxer! ");
        exit(1);
    }

    char chunk[128];
    char *token;

    while (fgets(chunk, sizeof(chunk), fp) != NULL)
    {
        token = strtok(chunk, " ");

        //fputs(chunk, stdout); // DEBUG FILE CONTENTS

        if(strcmp(token, "Id") == 0){

            token = strtok(NULL, " ");
            strcpy(id, token);

            id[strcspn(id, "\n")] = 0; //Per eliminar el "Newline"
            
            continue;
        }

        if(strcmp(token, "MAC") == 0){

            token = strtok(NULL, " ");
            strcpy(MAC, token);

            MAC[strcspn(MAC, "\n")] = 0; //Per eliminar el "Newline"
            
            continue;
        }

        if(strcmp(token, "NMS-Id") == 0){

            token = strtok(NULL, " ");
            strcpy(NMSId, token);

            NMSId[strcspn(NMSId, "\n")] = 0; //Per eliminar el "Newline"
            
            continue;
        }

        if(strcmp(token, "NMS-UDP-port") == 0){

            token = strtok(NULL, " ");
            strcpy(NMSUDPport, token);

            NMSUDPport[strcspn(NMSUDPport, "\n")] = 0; //Per eliminar el "Newline"
            
            continue;
        }
    }
    sprintf(debug_str, "S'ha llegit l'arxiu de dades de configuració del software: %s", filename);
    debug_log(debug_str);
    fclose(fp);

}

void debugConfigVars(){

    fputs(id, stdout);
    fputs(MAC, stdout);
    fputs(NMSId, stdout);
    fputs(NMSUDPport, stdout);

}

int main(int argc, char const *argv[])
{
    status = DISCONNECTED; // El client partirà del estat DISCONNECTED
    print_message("L'equip passa al estat [DISCONNECTED]");

    readParameters(argc, argv);
    saveConfig(client_cfg_file);

    struct hostent *ent;

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0); // Crear el socket
    
    ent = gethostbyname(NMSId); // Traduir localhost a 127.0.0.1

    if(udp_sock < 0){
        fprintf(stderr, "No s'ha pogut obrir el socket UDP. \n");
        exit(-1);
    }

    /* Adreça del bind del client */
    memset(&addr_cli_udp, 0, sizeof(struct sockaddr_in));
    addr_cli_udp.sin_family = AF_INET;
    addr_cli_udp.sin_addr.s_addr=htonl(INADDR_ANY);
    addr_cli_udp.sin_port=htons(0);

    /* fer bind i controlar errors */
    if(bind(udp_sock,(struct sockaddr *)&addr_cli_udp,sizeof(struct sockaddr_in))<0)
	{
		fprintf(stderr,"No s'ha pogut fer binding del socket. \n");
        exit(-2);
	}

    /* Adreça del servidor */
    memset(&addr_server_udp, 0, sizeof(struct sockaddr_in));
	addr_server_udp.sin_family=AF_INET;
	addr_server_udp.sin_addr.s_addr=(((struct in_addr *)ent->h_addr_list[0])->s_addr);
	addr_server_udp.sin_port=htons(atoi(NMSUDPport));

    /* 1.- Enviar petició de registre [REGISTER_REQ] */
    strcpy(pdu_udp_send.random_num, "000000"); //Valors del camp aleatori a zero


    registerPhase();
    //debugConfigVars();

}
