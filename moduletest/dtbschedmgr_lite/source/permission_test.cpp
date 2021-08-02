/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include <dirent.h>
#include <fstream>
#include <securec.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

#include "bundle_manager.h"
#include "dmsfwk_interface.h"
#include "dmslite_permission.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
#ifndef WEARABLE_PRODUCT
const int32_t MAX_APPID_LEN = 512;
const int32_t NON_EXISTENT_UID = 12345;
const char NATIVE_APPID_DIR[] = "/system/native_appid/";
const char FOUNDATION_APPID[] = "foundation_signature";
const char PREFIX[] = "uid_";
const char SUFFIX[] = "_appid";
const char LAUNCHER_BUNDLE_NAME[] = "com.huawei.launcher";
const char LAUNCHER_APPID[] = "com.huawei.launcher_BM70W1/aVSbkx+uI/WT/mO9NqmtEBx9esLAogYAid75/gTMpKWqrNUT5hS9Cj"
                              "Bq6kt1OcxgZzdCJ4HuVyS4dP8w=";
#endif
}

class PermissionTest : public testing::Test {
protected:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    virtual void SetUp() { }
    virtual void TearDown() { }
};

#ifndef WEARABLE_PRODUCT
/**
 * @tc.name: GetAppId_001
 * @tc.desc: Get appId failed with invalid appId pointer or length
 * @tc.type: FUNC
 * @tc.require: AR000FU5M6
 */
HWTEST_F(PermissionTest, GetAppId_001, TestSize.Level1)
{
    BundleInfo bundleInfo;
    EXPECT_EQ(memset_s(&bundleInfo, sizeof(BundleInfo), 0x00, sizeof(BundleInfo)), EOK);
    EXPECT_EQ(GetBundleInfo(LAUNCHER_BUNDLE_NAME, 0, &bundleInfo), EC_SUCCESS);
    CallerInfo callerInfo;
    callerInfo.uid = bundleInfo.uid;
    char *appId1 = nullptr;
    EXPECT_EQ(GetAppId(&callerInfo, appId1, MAX_APPID_LEN), DMS_EC_INVALID_PARAMETER);
    char appId2[MAX_APPID_LEN] = {0};
    EXPECT_EQ(GetAppId(&callerInfo, appId2, 0), DMS_EC_INVALID_PARAMETER);
    EXPECT_EQ(GetAppId(nullptr, appId2, MAX_APPID_LEN), DMS_EC_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAppId_002
 * @tc.desc: Get appId failed with SHELL_UID=2, which is not configured with appId
 * @tc.type: FUNC
 * @tc.require: AR000FU5M6
 */
HWTEST_F(PermissionTest, GetAppId_002, TestSize.Level1)
{
    char appId[MAX_APPID_LEN] = {0};
    CallerInfo callerInfo;
    callerInfo.uid = SHELL_UID;
    EXPECT_EQ(GetAppId(&callerInfo, appId, MAX_APPID_LEN), DMS_EC_FAILURE);
}

/**
 * @tc.name: GetAppId_003
 * @tc.desc: Get appId successfully with FOUNDATION_UID=7, which has been configured with appId
 * @tc.type: FUNC
 * @tc.require: AR000FU5M6
 */
HWTEST_F(PermissionTest, GetAppId_003, TestSize.Level1)
{
    bool isDirExist = true;
    DIR *dir = opendir(NATIVE_APPID_DIR);
    if (dir == nullptr) {
        mode_t mode = 0700;
        EXPECT_EQ(mkdir(NATIVE_APPID_DIR, mode), 0);
        isDirExist = false;
    } else {
        closedir(dir);
    }
    CallerInfo callerInfo;
    callerInfo.uid = FOUNDATION_UID;
    stringstream filePath;
    filePath << NATIVE_APPID_DIR << PREFIX << callerInfo.uid << SUFFIX;
    fstream fs(filePath.str(), ios::out);
    EXPECT_TRUE(fs.is_open());
    fs << FOUNDATION_APPID;
    fs.close();
    char appId[MAX_APPID_LEN] = {0};
    EXPECT_EQ(GetAppId(&callerInfo, appId, MAX_APPID_LEN), DMS_EC_SUCCESS);
    EXPECT_EQ(strcmp(appId, FOUNDATION_APPID), 0);
    remove(filePath.str().c_str());
    if (!isDirExist) {
        rmdir(NATIVE_APPID_DIR);
    }
}

/**
 * @tc.name: GetAppId_004
 * @tc.desc: Get appId failed with a non-existent uid
 * @tc.type: FUNC
 * @tc.require: AR000FU5M6
 */
HWTEST_F(PermissionTest, GetAppId_004, TestSize.Level1)
{
    char appId[MAX_APPID_LEN] = {0};
    CallerInfo callerInfo;
    callerInfo.uid = NON_EXISTENT_UID;
    EXPECT_EQ(GetAppId(&callerInfo, appId, MAX_APPID_LEN), DMS_EC_FAILURE);
}

/**
 * @tc.name: GetAppId_005
 * @tc.desc: Get appId successfully with com.huawei.launcher uid
 * @tc.type: FUNC
 * @tc.require: AR000FU5M6
 */
HWTEST_F(PermissionTest, GetAppId_005, TestSize.Level1)
{
    BundleInfo bundleInfo;
    EXPECT_EQ(memset_s(&bundleInfo, sizeof(BundleInfo), 0x00, sizeof(BundleInfo)), EOK);
    EXPECT_EQ(GetBundleInfo(LAUNCHER_BUNDLE_NAME, 0, &bundleInfo), EC_SUCCESS);
    CallerInfo callerInfo;
    callerInfo.uid = bundleInfo.uid;
    char appId[MAX_APPID_LEN] = {0};
    EXPECT_EQ(GetAppId(&callerInfo, appId, MAX_APPID_LEN), DMS_EC_SUCCESS);
    EXPECT_EQ(strcmp(appId, LAUNCHER_APPID), 0);
}
#endif
}
}
