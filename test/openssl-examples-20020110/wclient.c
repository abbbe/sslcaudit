/* A simple HTTPS client

   It connects to the server, makes an HTTP
   request and waits for the response
*/
#include "common.h"
#include "client.h"

static char *REQUEST_TEMPLATE=
   "GET / HTTP/1.0\r\nUser-Agent:"
   "EKRClient\r\nHost: %s:%d\r\n\r\n";

static char *host=HOST;
static int port=PORT;
static int require_server_auth=1;

static int http_request(ssl)
  SSL *ssl;
  {
    char *request=0;
    char buf[BUFSIZZ];
    int r;
    int len, request_len;
    
    /* Now construct our HTTP request */
    request_len=strlen(REQUEST_TEMPLATE)+
      strlen(host)+6;
    if(!(request=(char *)malloc(request_len)))
      err_exit("Couldn't allocate request");
    snprintf(request,request_len,REQUEST_TEMPLATE,
      host,port);

    /* Find the exact request_len */
    request_len=strlen(request);

    r=SSL_write(ssl,request,request_len);
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
    }
    
    /* Now read the server's response, assuming
       that it's terminated by a close */
    while(1){
      r=SSL_read(ssl,buf,BUFSIZZ);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          fprintf(stderr,
            "SSL Error: Premature close\n");
          goto done;
        default:
          berr_exit("SSL read problem");
      }

      fwrite(buf,1,len,stdout);
    }
    
  shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }
    
  done:
    SSL_free(ssl);
    free(request);
    return(0);
  }
    
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

    while((c=getopt(argc,argv,"h:p:i"))!=-1){
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
      }
    }

    /* Build our SSL context*/
    ctx=initialize_ctx(KEYFILE,PASSWORD);

    /* Connect the TCP socket*/
    sock=tcp_connect(host,port);

    /* Connect the SSL socket */
    ssl=SSL_new(ctx);
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);

    if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
    if(require_server_auth)
      check_cert(ssl,host);
 
    /* Now make our HTTP request */
    http_request(ssl);

    /* Shutdown the socket */
    destroy_ctx(ctx);
    close(sock);

    exit(0);
  }

