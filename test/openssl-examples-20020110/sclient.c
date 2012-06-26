/* A simple SSL client.

   It connects and then forwards data from/to the terminal
   to/from the server
*/
#include "common.h"
#include "client.h"
#include "read_write.h"

static char *host=HOST;
static int port=PORT;
static int require_server_auth=1;
static char *ciphers=0;

static int s_server_session_id_context = 1;

int main(argc,argv)
  int argc;
  char **argv;
  {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    int sock;

    
    extern char *optarg;
    int c;

    while((c=getopt(argc,argv,"h:p:ia:r"))!=-1){
      switch(c){
        case 'h':
          if(!(host=strdup(optarg)))
            err_exit("Out of memory");
          break;
        case 'p':
          if(!(port=atoi(optarg)))
            err_exit("Bogus port specified");
          break;
        case 'i':
          require_server_auth=0;
          break;
        case 'a':
          if(!(ciphers=strdup(optarg)))
            err_exit("Out of memory");
          break;
      }
    }
    
    /* Build our SSL context*/
    ctx=initialize_ctx(KEYFILE,PASSWORD);

    /* Set our cipher list */
    if(ciphers){
      SSL_CTX_set_cipher_list(ctx,ciphers);
    }
    
    SSL_CTX_set_session_id_context(ctx,
      (void*)&s_server_session_id_context,
      sizeof s_server_session_id_context); 
    
    /* Connect the TCP socket*/
    sock=tcp_connect(host,port);

    /* Connect the SSL socket */
    ssl=SSL_new(ctx);
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);
    if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
    check_cert(ssl,host);

    /* read and write */
    read_write(ssl,sock);

    destroy_ctx(ctx);

    exit(0);
  }

