 /* A simple HTTPS server */
#include "common.h"
#include "server.h"

static int http_serve(ssl,s)
  SSL *ssl;
  int s;
  {
    char buf[BUFSIZZ];
    int r,len;
    BIO *io,*ssl_bio;
    
    io=BIO_new(BIO_f_buffer());
    ssl_bio=BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio,ssl,BIO_CLOSE);
    BIO_push(io,ssl_bio);
    
    while(1){
      r=BIO_gets(io,buf,BUFSIZZ-1);

      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        default:
          berr_exit("SSL read problem");
      }

      /* Look for the blank line that signals
         the end of the HTTP headers */
      if(!strcmp(buf,"\r\n") ||
        !strcmp(buf,"\n"))
        break;
    }

    if((r=BIO_puts
      (io,"HTTP/1.0 200 OK\r\n"))<=0)
      err_exit("Write error");
    if((r=BIO_puts
      (io,"Server: EKRServer\r\n\r\n"))<=0)
      err_exit("Write error");
    if((r=BIO_puts
      (io,"Server test page\r\n"))<=0)
      err_exit("Write error");
    
    if((r=BIO_flush(io))<0)
      err_exit("Error flushing BIO");


    
    r=SSL_shutdown(ssl);
    if(!r){
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify*/
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }
      
    switch(r){  
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }

    SSL_free(ssl);
    close(s);

    return(0);
  }
 
int main(argc,argv)
  int argc;
  char **argv;
  {
    int sock,s;
    BIO *sbio;
    SSL_CTX *ctx;
    SSL *ssl;
    int r;
    pid_t pid;
    
    /* Build our SSL context*/
    ctx=initialize_ctx(KEYFILE,PASSWORD);
    load_dh_params(ctx,DHFILE);
   
    sock=tcp_listen();

    while(1){
      if((s=accept(sock,0,0))<0)
        err_exit("Problem accepting");

      if((pid=fork())){
        close(s);
      }
      else {
        sbio=BIO_new_socket(s,BIO_NOCLOSE);
        ssl=SSL_new(ctx);
        SSL_set_bio(ssl,sbio,sbio);
        
        if((r=SSL_accept(ssl)<=0))
          berr_exit("SSL accept error");
        
        http_serve(ssl,s);
        exit(0);
      }
    }
    destroy_ctx(ctx);
    exit(0);
  }
