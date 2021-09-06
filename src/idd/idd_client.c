#include <oc_api.h>
#include <oc_rep.h>
#include <port/oc_clock.h>
#include <signal.h>
#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

int quit = 0;

#ifdef WIN32
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;
#else
pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;
#endif

static int
app_init(void)
{
    int ret = oc_init_platform("Apple", NULL, NULL);
    ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
        "ocf.res.1.0.0", NULL, NULL);
    return ret;
}

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;

static bool state;
static int power;
static oc_string_t name;

static void
get_idd(oc_client_response_t *data)
{
    PRINT("GET_idd:\n");
    oc_rep_t *rep = data->payload;

    char * json;
    size_t json_size;
    json_size = oc_rep_to_json(rep, NULL, 0, true);
    json = (char *)malloc(json_size + 1);
    oc_rep_to_json(rep, json, json_size + 1, true);
    printf("%s", json);
    free(json);
}

static void
get_introspection(oc_client_response_t *data)
{
    PRINT("GET_introspection:\n");
    oc_rep_t *rep = data->payload;

    char * json;
    size_t json_size;
    json_size = oc_rep_to_json(rep, NULL, 0, true);
    json = (char *)malloc(json_size + 1);
    oc_rep_to_json(rep, json, json_size + 1, true);
    printf("%s", json);
    free(json);

    oc_do_get("/oc/introspection", light_server, "if=oic.if.baseline", &get_idd, LOW_QOS, NULL);
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
    oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
    oc_resource_properties_t bm, void *user_data)
{
    (void)anchor;
    (void)user_data;
    (void)iface_mask;
    (void)bm;
    int i;
    size_t uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
    PRINT("\n\nDISCOVERYCB %s %s %zd\n\n", anchor, uri,
        oc_string_array_get_allocated_size(types));
    for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
        char *t = oc_string_array_get_item(types, i);
        PRINT("\n\nDISCOVERED RES %s\n\n\n", t);
        if (strlen(t) == 19 && strncmp(t, "oic.r.switch.binary", 19) == 0) {
            oc_endpoint_list_copy(&light_server, endpoint);
            strncpy(a_light, uri, uri_len);
            a_light[uri_len] = '\0';

            PRINT("Resource %s hosted at endpoints:\n", a_light);
            oc_endpoint_t *ep = endpoint;
            while (ep != NULL) {
                PRINTipaddr(*ep);
                PRINT("\n");
                ep = ep->next;
            }

            oc_do_get("/oc/wk/introspection", light_server, "if=oic.if.baseline", &get_introspection, LOW_QOS, NULL);

            return OC_STOP_DISCOVERY;
        }
    }
    return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
    oc_do_ip_discovery("oic.r.switch.binary", &discovery, NULL);
}

static void
signal_event_loop(void)
{
#ifdef WIN32
    WakeConditionVariable(&cv);
#else
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
#endif
}

void
handle_signal(int signal)
{
    signal_event_loop();
    quit = 1;
}

int
main(void)
{
    int init;
#ifdef WIN32
    InitializeCriticalSection(&cs);
    InitializeConditionVariable(&cv);
    signal(SIGINT, handle_signal);
#else
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
#endif

    static const oc_handler_t handler = { .init = app_init,
                                          .signal_event_loop = signal_event_loop,
                                          .register_resources = 0,
                                          .requests_entry = issue_requests };

    oc_clock_time_t next_event;

    init = oc_main_init(&handler);
    if (init < 0)
        return init;

    while (quit != 1) {
#ifdef WIN32
        next_event = oc_main_poll();
        if (next_event == 0) {
            SleepConditionVariableCS(&cv, &cs, INFINITE);
        } else {
            oc_clock_time_t now = oc_clock_time();
            if (now < next_event) {
                SleepConditionVariableCS(
                    &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
            }
        }
#else
        next_event = oc_main_poll();
        pthread_mutex_lock(&mutex);
        if (next_event == 0) {
            pthread_cond_wait(&cv, &mutex);
        } else {
            ts.tv_sec = (next_event / OC_CLOCK_SECOND);
            ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
            pthread_cond_timedwait(&cv, &mutex, &ts);
        }
        pthread_mutex_unlock(&mutex);
#endif
    }

    oc_main_shutdown();
    return 0;
}
