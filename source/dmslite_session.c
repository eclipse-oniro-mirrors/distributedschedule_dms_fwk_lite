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
#include "dmslite_feature.h"
#include "dmslite_log.h"
#include "dmslite_pack.h"
#include "dmslite_parser.h"
#include "dmslite_utils.h"

#include "securec.h"
#include "session.h"
#include "softbus_common.h"

#define DMS_SESSION_NAME "ohos.distributedschedule.dms.proxymanager"
#define DMS_MODULE_NAME "dms"

#define INVALID_SESSION_ID (-1)
#define MAX_DATA_SIZE 256
#define TIMEOUT 60

static int32_t g_curSessionId = INVALID_SESSION_ID;
static bool g_curBusy = false;
static time_t g_begin;
static IDmsListener *g_listener = NULL;

/* session callback */
static void OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen);
static void OnSessionClosed(int32_t sessionId);
static int32_t OnSessionOpened(int32_t sessionId, int result);
static void OnMessageReceived(int sessionId, const void *data, unsigned int len);

static bool IsTimeOut();

static void OnStartAbilityDone(int8_t errCode);

static ISessionListener g_sessionCallback = {
    .OnBytesReceived = OnBytesReceived,
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnMessageReceived = OnMessageReceived
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
    // CreateDMSSessionServer();
}

void OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    HILOGD("[OnBytesReceived dataLen = %d]", dataLen);
    if (data == NULL || dataLen > MAX_DATA_SIZE) {
        HILOGE("[OnBytesReceived param error");
        return;
    }
    char *message = (char *)DMS_ALLOC(dataLen);
    if (message == NULL) {
        return;
    }
    if (memcpy_s(message, dataLen, (char *)data, dataLen) != EOK) {
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
    Request request = {
        .msgId = SESSION_CLOSE,
        .len = 0,
        .data = NULL,
        .msgValue = sessionId
    };
    int32_t result = SAMGR_SendRequest((const Identity*)&(GetDmsLiteFeature()->identity), &request, NULL);
    if (result != EC_SUCCESS) {
        HILOGD("[OnSessionClosed SendRequest errCode = %d]", result);
    }
}

void HandleSessionClosed(int32_t sessionId)
{
    if (g_curSessionId == sessionId && !g_curBusy) {
        g_curSessionId = INVALID_SESSION_ID;
        g_curBusy = false;
    }
}

int32_t OnSessionOpened(int32_t sessionId, int result)
{
    HILOGD("[OnSessionOpened result = %d]", result);
    if (sessionId < 0 || result != 0) {
        HILOGD("[OnSessionOpened errCode = %d]", result);
        return result;
    }

    Request request = {
        .msgId = SESSION_OPEN,
        .len = 0,
        .data = NULL,
        .msgValue = sessionId
    };
    int32_t ret = SAMGR_SendRequest((const Identity*)&(GetDmsLiteFeature()->identity), &request, NULL);
    if (ret != EC_SUCCESS) {
        HILOGD("[OnSessionOpened SendRequest errCode = %d]", ret);
    }
    return ret;
}

int32_t HandleSessionOpened(int32_t sessionId)
{
    if (g_curSessionId != sessionId) {
        return EC_SUCCESS;
    }
    int32_t ret = SendBytes(g_curSessionId, GetPacketBufPtr(), GetPacketSize());
    if (ret != 0) {
        HILOGD("[OnSessionOpened SendBytes errCode = %d]", ret);
        CloseDMSSession();
    }
    CleanBuild();
    return ret;
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

int32_t SendDmsMessage(char *data, int32_t len, const char *deviceId, const IDmsListener *callback)
{
    HILOGI("[SendMessage]");
    if (data == NULL || len > MAX_DATA_SIZE) {
        HILOGE("[SendMessage params error]");
        return EC_FAILURE;
    }

    if (g_curBusy && IsTimeOut() && g_curSessionId >= 0) {
        CloseDMSSession();
    }

    if (g_curBusy) {
        HILOGE("[SendDmsMessage busy]");
        return EC_FAILURE;
    }

    g_curBusy = true;
    g_listener = callback;
    g_begin = time(NULL);

    SessionAttribute attr = {
        .dataType = TYPE_BYTES
    };
    g_curSessionId = OpenSession(DMS_SESSION_NAME, DMS_SESSION_NAME, deviceId, DMS_MODULE_NAME, &attr);
    if (g_curSessionId < 0) {
        g_curSessionId = INVALID_SESSION_ID;
        g_curBusy = false;
        g_listener = NULL;
        return EC_FAILURE;
    }
    return EC_SUCCESS;
}

void CloseDMSSession()
{
    CloseSession(g_curSessionId);
    g_curSessionId = INVALID_SESSION_ID;
    g_curBusy = false;
    g_listener = NULL;
}

void InvokeCallback(const void *data, int32_t result)
{
    if (g_listener == NULL) {
        return;
    }
    g_listener->OnResultCallback(data, result);
}

static bool IsTimeOut()
{
    time_t now = time(NULL);
    HILOGI("[IsTimeOut diff %f]", difftime(now, g_begin));
    return ((int)difftime(now, g_begin)) - TIMEOUT >= 0;
}

bool IsDmsBusy()
{
    return g_curBusy;
}