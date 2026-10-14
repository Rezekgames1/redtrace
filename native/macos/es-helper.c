// Notification-only ES source. Bounded ring keeps disk/pipe IO outside ES callbacks.
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#define SLOTS 64
#define RECORD_BYTES 16384
typedef struct { char data[RECORD_BYTES]; size_t length; } record_t;
static record_t queue[SLOTS];
static size_t head, count;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t available = PTHREAD_COND_INITIALIZER;
static atomic_ulong dropped;
static char session[96];
typedef struct { char *data; size_t length; bool truncated; } json_t;
static void append(json_t *j, const char *s, size_t n) {
    if (n >= RECORD_BYTES - j->length - 2) { j->truncated = true; return; }
    memcpy(j->data + j->length, s, n); j->length += n;
}
static void literal(json_t *j, const char *s) { append(j, s, strlen(s)); }
static void string(json_t *j, const char *s, size_t n) {
    literal(j, "\"");
    for (size_t i = 0; i < n && i < 4096; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { char pair[2] = {'\\', (char)c}; append(j, pair, 2); }
        else if (c < 32) { char escaped[7]; snprintf(escaped, sizeof escaped, "\\u%04x", c); literal(j, escaped); }
        else append(j, &s[i], 1);
    }
    if (n > 4096) j->truncated = true;
    literal(j, "\"");
}
static void field(json_t *j, const char *key, es_string_token_t value) {
    literal(j, ","); string(j, key, strlen(key)); literal(j, ":"); string(j, value.data, value.length);
}
static void number_field(json_t *j, const char *key, unsigned long long value) {
    char buffer[32]; int n = snprintf(buffer, sizeof buffer, "%llu", value);
    field(j, key, (es_string_token_t){.data=buffer,.length=(size_t)n});
}
static void outcome(json_t *j, bool success) {
    const char *value = success ? "success" : "failure";
    field(j, "event.outcome", (es_string_token_t){.data=value,.length=strlen(value)});
}
static void process(json_t *j, const es_process_t *p, uint32_t version) {
    number_field(j, "process.pid", audit_token_to_pid(p->audit_token));
    number_field(j, "process.pidversion", p->audit_token.val[7]);
    number_field(j, "process.parent.pid", p->ppid);
    number_field(j, "user.id", audit_token_to_ruid(p->audit_token));
    number_field(j, "user.effective.id", audit_token_to_euid(p->audit_token));
    field(j, "process.executable", p->executable->path);
    field(j, "process.code_signature.signing_id", p->signing_id);
    field(j, "process.code_signature.team_id", p->team_id);
    if (version >= 3) {
        char start[64]; int n = snprintf(start, sizeof start, "%lld.%06d", (long long)p->start_time.tv_sec, p->start_time.tv_usec);
        field(j, "process.start", (es_string_token_t){.data=start,.length=(size_t)n});
    }
}
static void *writer(void *unused) {
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&lock);
        while (count == 0) pthread_cond_wait(&available, &lock);
        record_t record = queue[head]; head = (head + 1) % SLOTS; count--;
        pthread_mutex_unlock(&lock);
        size_t written = 0;
        while (written < record.length) { ssize_t n = write(STDOUT_FILENO, record.data + written, record.length - written); if(n<0&&errno==EINTR)continue;if(n<=0)_exit(3);written+=(size_t)n; }
    }
    return NULL;
}
static void receive(const es_message_t *m) {
    if (audit_token_to_pid(m->process->audit_token) == getpid() || m->process->is_es_client) return;
    const char *action = NULL; const es_process_t *p=m->process; const es_file_t *file=NULL;
    switch(m->event_type){
        case ES_EVENT_TYPE_NOTIFY_EXEC:action="exec";p=m->event.exec.target;break;
        case ES_EVENT_TYPE_NOTIFY_FORK:action="fork";p=m->event.fork.child;break;
        case ES_EVENT_TYPE_NOTIFY_EXIT:action="exit";break;
        case ES_EVENT_TYPE_NOTIFY_CREATE:action="create";if(m->event.create.destination_type==ES_DESTINATION_TYPE_EXISTING_FILE)file=m->event.create.destination.existing_file;break;
        case ES_EVENT_TYPE_NOTIFY_RENAME:action="rename";file=m->event.rename.source;break;
        case ES_EVENT_TYPE_NOTIFY_UNLINK:action="unlink";file=m->event.unlink.target;break;
        case ES_EVENT_TYPE_NOTIFY_OPEN:action="open";file=m->event.open.file;break;
        case ES_EVENT_TYPE_NOTIFY_CLOSE:action="close";file=m->event.close.target;break;
        case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:action="authentication";break;
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:action="login_login";break;
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:action="login_logout";break;
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:action="openssh_login";break;
        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:action="openssh_logout";break;
        default:return;
    }
    record_t record={0};json_t j={.data=record.data};
    struct tm utc;gmtime_r(&m->time.tv_sec,&utc);char stamp[64],calendar[32];strftime(calendar,sizeof calendar,"%Y-%m-%dT%H:%M:%S",&utc);snprintf(stamp,sizeof stamp,"%s.%09ldZ",calendar,m->time.tv_nsec);
    literal(&j,"{\"redtrace_es\":1,\"timestamp\":");string(&j,stamp,strlen(stamp));literal(&j,",\"action\":");string(&j,action,strlen(action));literal(&j,",\"session\":");string(&j,session,strlen(session));
    char sequence[160];snprintf(sequence,sizeof sequence,",\"global_seq_num\":%llu,\"mach_time\":%llu,\"fields\":{\"es.dropped_total\":\"%lu\"",m->version>=4?m->global_seq_num:(m->version>=2?m->seq_num:0),m->mach_time,atomic_load(&dropped));literal(&j,sequence);process(&j,p,m->version);
    if(file)field(&j,"file.path",file->path);
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_EXEC){
        if(m->version>=3)field(&j,"process.working_directory",m->event.exec.cwd->path);
        char arguments[RECORD_BYTES]={0};json_t args={.data=arguments};literal(&args,"[");uint32_t argc=es_exec_arg_count(&m->event.exec);
        for(uint32_t i=0;i<argc&&i<128;i++){if(i)literal(&args,",");es_string_token_t arg=es_exec_arg(&m->event.exec,i);string(&args,arg.data,arg.length);}literal(&args,"]");if(args.truncated||argc>128)j.truncated=true;
        field(&j,"process.args",(es_string_token_t){.data=arguments,.length=args.length});
    }
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_RENAME){if(m->event.rename.destination_type==ES_DESTINATION_TYPE_EXISTING_FILE)field(&j,"file.target.path",m->event.rename.destination.existing_file->path);else{field(&j,"file.target.directory",m->event.rename.destination.new_path.dir->path);field(&j,"file.target.name",m->event.rename.destination.new_path.filename);}}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_CREATE&&m->event.create.destination_type==ES_DESTINATION_TYPE_NEW_PATH){field(&j,"file.directory",m->event.create.destination.new_path.dir->path);field(&j,"file.name",m->event.create.destination.new_path.filename);}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_EXIT){int status=m->event.exit.stat;number_field(&j,"process.exit_status",status);if(WIFEXITED(status))number_field(&j,"process.exit_code",WEXITSTATUS(status));else if(WIFSIGNALED(status))number_field(&j,"process.exit_signal",WTERMSIG(status));}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_AUTHENTICATION){const es_event_authentication_t *auth=m->event.authentication;outcome(&j,auth->success);number_field(&j,"authentication.type",auth->type);if(auth->type==ES_AUTHENTICATION_TYPE_OD){field(&j,"user.name",auth->data.od->record_name);field(&j,"authentication.node",auth->data.od->node_name);}else if(auth->type==ES_AUTHENTICATION_TYPE_AUTO_UNLOCK){field(&j,"user.name",auth->data.auto_unlock->username);}else if(auth->type==ES_AUTHENTICATION_TYPE_TOUCHID&&auth->data.touchid->has_uid){number_field(&j,"user.id",auth->data.touchid->uid.uid);}}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN){const es_event_login_login_t *login=m->event.login_login;outcome(&j,login->success);field(&j,"user.name",login->username);field(&j,"event.reason",login->failure_message);if(login->has_uid)number_field(&j,"user.id",login->uid.uid);}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT){const es_event_login_logout_t *logout=m->event.login_logout;field(&j,"user.name",logout->username);number_field(&j,"user.id",logout->uid);}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN){const es_event_openssh_login_t *login=m->event.openssh_login;outcome(&j,login->success);field(&j,"user.name",login->username);field(&j,"source.address",login->source_address);number_field(&j,"event.code",login->result_type);if(login->has_uid)number_field(&j,"user.id",login->uid.uid);}
    if(m->event_type==ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT){const es_event_openssh_logout_t *logout=m->event.openssh_logout;field(&j,"user.name",logout->username);field(&j,"source.address",logout->source_address);number_field(&j,"user.id",logout->uid);}
    literal(&j,"}}\n");if(j.truncated){atomic_fetch_add(&dropped,1);return;}record.length=j.length;
    if(pthread_mutex_trylock(&lock)!=0){atomic_fetch_add(&dropped,1);return;}if(count==SLOTS){atomic_fetch_add(&dropped,1);pthread_mutex_unlock(&lock);return;}queue[(head+count)%SLOTS]=record;count++;pthread_cond_signal(&available);pthread_mutex_unlock(&lock);
}
int main(int argc,char **argv){
    const char *names[]={"exec","fork","exit","create","rename","unlink","open","close","authentication","login_login","login_logout","openssh_login","openssh_logout"};const es_event_type_t types[]={ES_EVENT_TYPE_NOTIFY_EXEC,ES_EVENT_TYPE_NOTIFY_FORK,ES_EVENT_TYPE_NOTIFY_EXIT,ES_EVENT_TYPE_NOTIFY_CREATE,ES_EVENT_TYPE_NOTIFY_RENAME,ES_EVENT_TYPE_NOTIFY_UNLINK,ES_EVENT_TYPE_NOTIFY_OPEN,ES_EVENT_TYPE_NOTIFY_CLOSE,ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT,ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT};es_event_type_t selected[sizeof types/sizeof types[0]];uint32_t n=0;
    for(int i=1;i<argc;i++){const char *name=argv[i];if(strcmp(name,"ssh_login")==0)name="openssh_login";if(strcmp(name,"ssh_logout")==0)name="openssh_logout";bool found=false;for(size_t k=0;k<sizeof types/sizeof types[0];k++)if(strcmp(name,names[k])==0){bool duplicate=false;for(uint32_t p=0;p<n;p++)if(selected[p]==types[k])duplicate=true;if(!duplicate)selected[n++]=types[k];found=true;break;}if(!found){fprintf(stderr,"Unsupported native ES event: %s\n",argv[i]);return 2;}}
    if(!n){memcpy(selected,types,3*sizeof types[0]);n=3;}
    struct timespec now;clock_gettime(CLOCK_REALTIME,&now);snprintf(session,sizeof session,"%d-%lld-%ld",getpid(),(long long)now.tv_sec,now.tv_nsec);
    es_client_t *client=NULL;es_new_client_result_t result=es_new_client(&client,^(es_client_t *c,const es_message_t *m){(void)c;receive(m);});
    if(result!=ES_NEW_CLIENT_RESULT_SUCCESS){fprintf(stderr,"Endpoint Security unavailable: es_new_client=%d; requires root, Full Disk Access and com.apple.developer.endpoint-security.client entitlement\n",result);return 4;}
    pthread_t thread;if(pthread_create(&thread,NULL,writer,NULL)!=0)return 3;
    if(es_subscribe(client,selected,n)!=ES_RETURN_SUCCESS){fprintf(stderr,"Endpoint Security subscription failed\n");es_delete_client(client);return 3;}dispatch_main();
}
