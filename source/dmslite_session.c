/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dmslite_session.h"

#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>

#include "dmsfwk_interface.h"
#include "dmslite_devmgr.h"
#include "dmslite_feature.h"
#include "dmslite_log.h"
#include "dmslite_parser.h"
#include "dmslite_utils.h"

#include "securec.h"
#include "softbus_common.h"
#include "softbus_session.h"
#include "softbus_sys.h"

#define DMS_SESSION_NAME "com.huawei.harmonyos.foundation.dms"
#define DMS_MODULE_NAME "dms"

#define TIME_SS_US 1000000
#define TIME_US_MS 1000
#define TIME_US_NS 1000000000
#define TIME_OUT 10000
#define INVALID_SESSION_ID (-1)
#define MAX_DATA_SIZE 256

static int32_t g_curSessionId = INVALID_SESSION_ID;
static pthread_mutex_t g_mutex;
static pthread_cond_t g_cond;

/* session callback */
static void OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen);
static void OnSessionClosed(int32_t sessionId);
static int32_t OnSessionOpened(int32_t sessionId, int result);
static void OnMessageReceived(int sessionId, const void *data, unsigned int len);

static void NotifyConnected(void);
static void WaitForConnected(int timeOut);
static void GetCondTime(struct timespec *tv, int timeDelay);

static void OnStartAbilityDone(int8_t errCode);

static ISessionListener g_sessionCallback = {
    .onBytesReceived = OnBytesReceived,
    .onSessionOpened = OnSessionOpened,
    .onSessionClosed = OnSessionClosed,
    .onMessageReceived = OnMessageReceived
};

static IDmsFeatureCallback g_dmsFeatureCallback = {
    /* in non-test mode, there is no need set a TlvParseCallback */
    .onTlvParseDone = NULL,
    .onStartAbilityDone = OnStartAbilityDone,
};

void OnStartAbilityDone(int8_t errCode)
{
    HILOGD("[onStartAbilityDone errCode = %d]", errCode);
}

void InitSoftbusService()
{
    pthread_mutex_init(&g_mutex, NULL);
    pthread_cond_init(&g_cond, NULL);
    InitSoftBus(DMS_MODULE_NAME);
    AddDevMgrListener();
}

void OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    if (dataLen > MAX_DATA_SIZE || dataLen <= 0) {
        return;
    }
    char *message = (char *)DMS_ALLOC(dataLen);
    if (message == NULL) {
        return;
    }
    if (strncpy_s(message, dataLen, (char *)data, dataLen) != EOK) {
        return;
    }
    Request request = {
        .msgId = BYTES_RECEIVED,
        .len = dataLen,
        .data = message,
        .msgValue = sessionId
    };
    int32_t result = SAMGR_SendRequest((const Identity*)&(GetDmsLiteFeature()->identity), &request, NULL);
    if (result != EC_SUCCESS) {
        HILOGD("[OnBytesReceived errCode = %d]", result);
    }
}

void HandleBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    CommuMessage commuMessage;
    commuMessage.payloadLength = dataLen;
    commuMessage.payload = (uint8_t *)data;

    int32_t errCode = ProcessCommuMsg(&commuMessage, &g_dmsFeatureCallback);

    HILOGI("[ProcessCommuMsg errCode = %d]", errCode);
}

void OnSessionClosed(int32_t sessionId)
{
}

void HandleSessionClosed(int32_t sessionId)
{
}

int32_t OnSessionOpened(int32_t sessionId, int result)
{
    if (g_curSessionId == sessionId) {
        NotifyConnected();
    }
    return EC_SUCCESS;
}

int32_t HandleSessionOpened(int32_t sessionId)
{
    return EC_SUCCESS;
}

void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    return;
}

int32_t CreateDMSSessionServer()
{
    return CreateSessionServer(DMS_MODULE_NAME, DMS_SESSION_NAME, &g_sessionCallback);
}

int32_t CloseDMSSessionServer()
{
    return RemoveSessionServer(DMS_MODULE_NAME, DMS_SESSION_NAME);
}

int32_t SendDmsMessage(char *data, int32_t len)
{
    HILOGI("[SendMessage]");
    SessionAttribute attr = { .dataType = TYPE_BYTES };
    g_curSessionId = OpenSession(DMS_SESSION_NAME, DMS_SESSION_NAME, GetPeerId(), DMS_MODULE_NAME, &attr);
    if (g_curSessionId < 0) {
        return EC_FAILURE;
    }
    WaitForConnected(TIME_OUT);
    int32_t ret = SendBytes(g_curSessionId, data, len);
    if (ret != EC_SUCCESS) {
        return EC_FAILURE;
    }
    return EC_SUCCESS;
}

void CloseDMSSession()
{
    CloseSession(g_curSessionId);
    g_curSessionId = INVALID_SESSION_ID;
}

static void NotifyConnected(void)
{
    pthread_mutex_lock(&g_mutex);
    pthread_cond_signal(&g_cond);
    pthread_mutex_unlock(&g_mutex);
}

/* timeOut: The unit is milliseconds */
static void WaitForConnected(int timeOut)
{
    pthread_mutex_lock(&g_mutex);
    struct timespec tv;
    GetCondTime(&tv, timeOut);
    pthread_cond_timedwait(&g_cond, &g_mutex, &tv);
    pthread_mutex_unlock(&g_mutex);
}

static void GetCondTime(struct timespec *tv, int timeDelay)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    long nsec = now.tv_usec * TIME_US_MS + (timeDelay % TIME_US_MS) * TIME_SS_US;
    tv->tv_sec = now.tv_sec + nsec / TIME_US_NS + timeDelay / TIME_US_MS;
    tv->tv_nsec = nsec % TIME_US_NS;
}