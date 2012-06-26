/* A simple HTTPS server */
#include "common.h"
#include "server.h"

static int client_auth=0;
static int fork_child=1;
static char *ciphers=0;

#define CLIENT_AUTH_REQUEST 1
#define CLIENT_AUTH_REQUIRE 2
#define CLIENT_AUTH_REHANDSHAKE 3

static int s_server_session_id_context = 1;
static int s_server_auth_session_id_context = 2;

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
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
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

    /* Now perform renegotiation if requested */
    if(client_auth==CLIENT_AUTH_REHANDSHAKE){
      SSL_set_verify(ssl,SSL_VERIFY_PEER |
        SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);

      /* Stop the client from just resuming the
         un-authenticated session */
      SSL_set_session_id_context(ssl,
        (void *)&s_server_auth_session_id_context,
        sizeof(s_server_auth_session_id_context));
      
      if(SSL_renegotiate(ssl)<=0)
        berr_exit("SSL renegotiation error");
      if(SSL_do_handshake(ssl)<=0)
        berr_exit("SSL renegotiation error");
      ssl->state=SSL_ST_ACCEPT;
      if(SSL_do_handshake(ssl)<=0)
        berr_exit("SSL renegotiation error");
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


  shutdown:
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
    extern char *optarg;
    int c;

    while((c=getopt(argc,argv,"cCxna:"))!=-1){
      switch(c){
        case 'c':
          client_auth=CLIENT_AUTH_REQUEST;
          break;
        case 'C':
          client_auth=CLIENT_AUTH_REQUIRE;
          break;
        case 'x':
          client_auth=CLIENT_AUTH_REHANDSHAKE;
          break;
        case 'n':
          fork_child=0;
          break;
        case 'a':
          if(!(ciphers=strdup(optarg)))
            err_exit("Out of memory");
          break;
      }
    }
    
    /* Build our SSL context*/
    ctx=initialize_ctx(KEYFILE,PASSWORD);
    load_dh_params(ctx,DHFILE);

    SSL_CTX_set_session_id_context(ctx,
      (void*)&s_server_session_id_context,
      sizeof s_server_session_id_context); 
    
    /* Set our cipher list */
    if(ciphers){
      SSL_CTX_set_cipher_list(ctx,ciphers);
    }
    
    switch(client_auth){
      case CLIENT_AUTH_REQUEST:
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,0);
        break;
      case CLIENT_AUTH_REQUIRE:
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER |
          SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);
        break;
      case CLIENT_AUTH_REHANDSHAKE:
        /* Do nothing */
        break;
    }
    
    sock=tcp_listen();

    while(1){
      if((s=accept(sock,0,0))<0)
        err_exit("Problem accepting");

      if(fork_child && (pid=fork())){
        close(s);
      }
      else {
        sbio=BIO_new_socket(s,BIO_NOCLOSE);
        ssl=SSL_new(ctx);
        SSL_set_bio(ssl,sbio,sbio);
        
        if((r=SSL_accept(ssl)<=0))
          berr_exit("SSL accept error");
        
        http_serve(ssl,s);
        
        if(fork_child)
          exit(0);
      }
    }
    destroy_ctx(ctx);
    exit(0);
  }
