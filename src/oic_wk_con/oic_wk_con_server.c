#include <oc_api.h>
#include <oc_core_res.h>
#include <oc_rep.h>
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

static bool state = false;
int power;
oc_string_t name;

static int
app_init(void)
{
    int ret = oc_init_platform("Intel", NULL, NULL);
    ret |= oc_add_device("/oic/d", "oic.d.light.0", "Lamp 0", "ocf.1.0.0",
        "ocf.res.1.0.0", NULL, NULL);
    ret |= oc_add_device("/oic/d", "oic.d.light.1", "Lamp 1", "ocf.1.0.0",
        "ocf.res.1.0.0", NULL, NULL);
    oc_new_string(&name, "John's Light", 12);

    return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask,
    void *user_data)
{
    (void)user_data;
    ++power;

    PRINT("GET_light:\n");
    oc_rep_start_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
    case OC_IF_RW:
        oc_rep_set_boolean(root, state, state);
        oc_rep_set_int(root, power, power);
        oc_rep_set_text_string(root, name, oc_string(name));
        break;
    default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t iface_mask,
    void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    PRINT("POST_light:\n");
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
        PRINT("key: %s ", oc_string(rep->name));
        switch (rep->type) {
        case OC_REP_BOOL:
            state = rep->value.boolean;
            PRINT("value: %d\n", state);
            break;
        case OC_REP_INT:
            power = (int)rep->value.integer;
            PRINT("value: %d\n", power);
            break;
        case OC_REP_STRING:
            oc_free_string(&name);
            oc_new_string(&name, oc_string(rep->value.string),
                oc_string_len(rep->value.string));
            break;
        default:
            oc_send_response(request, OC_STATUS_BAD_REQUEST);
            return;
            break;
        }
        rep = rep->next;
    }
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t iface_mask,
    void *user_data)
{
    (void)iface_mask;
    (void)user_data;
    post_light(request, iface_mask, user_data);
}

static void
register_resources(void)
{
    oc_resource_t *res = oc_new_resource(NULL, "/a/light/0", 2, 0);
    oc_resource_bind_resource_type(res, "core.light.0");
    oc_resource_bind_resource_type(res, "core.brightlight.0");
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, 1);
    oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
    oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
    oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
    oc_add_resource(res);

    oc_resource_t* res1 = oc_new_resource(NULL, "/a/light/1", 2, 1);
    oc_resource_bind_resource_type(res1, "core.light.1");
    oc_resource_bind_resource_type(res1, "core.brightlight.1");
    oc_resource_bind_resource_interface(res1, OC_IF_RW);
    oc_resource_set_default_interface(res1, OC_IF_RW);
    oc_resource_set_discoverable(res1, true);
    oc_resource_set_periodic_observable(res1, 1);
    oc_resource_set_request_handler(res1, OC_GET, get_light, NULL);
    oc_resource_set_request_handler(res1, OC_PUT, put_light, NULL);
    oc_resource_set_request_handler(res1, OC_POST, post_light, NULL);
    oc_add_resource(res1);
}

void con_notification(size_t device_index, oc_rep_t *rep)
{
    PRINT("oic.wk.con resources has changed on device: %zd\n", device_index);

    char * json;
    size_t json_size;
    json_size = oc_rep_to_json(rep, NULL, 0, true);
    json = (char *)malloc(json_size + 1);
    oc_rep_to_json(rep, json, json_size + 1, true);
    printf("%s", json);
    free(json);
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
                                         .register_resources = register_resources,
                                         .requests_entry = 0 };

    oc_clock_time_t next_event;

    oc_set_con_res_announced(true);

    init = oc_main_init(&handler);
    if (init < 0)
        return init;

    oc_set_con_write_cb(con_notification);

    while (quit != 1) {
#ifdef WIN32
        next_event = oc_main_poll();
        if (next_event == 0) {
            SleepConditionVariableCS(&cv, &cs, INFINITE);
        } else {
            oc_clock_time_t now = oc_clock_time();
            if (now < next_event) {
                SleepConditionVariableCS(&cv, &cs,
                    (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
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
