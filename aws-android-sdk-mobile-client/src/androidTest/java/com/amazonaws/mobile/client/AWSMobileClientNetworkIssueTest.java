package com.amazonaws.mobile.client;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.internal.keyvaluestore.AWSKeyValueStore;
import com.amazonaws.mobile.config.AWSConfiguration;
import com.amazonaws.mobileconnectors.cognitoidentityprovider.CognitoUserPool;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidentityprovider.AmazonCognitoIdentityProvider;
import com.amazonaws.services.cognitoidentityprovider.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidentityprovider.model.InitiateAuthResult;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Userpool and identity pool were create with Amplify CLI 0.1.23 Default configuration
 */
@RunWith(AndroidJUnit4.class)
public class AWSMobileClientNetworkIssueTest extends AWSMobileClientTestBase {
    private static final String TAG = AWSMobileClientTest.class.getSimpleName();

    public static final String EMAIL = "somebody@email.com";
    public static final String BLURRED_EMAIL = "s***@e***.com";
    public static final String USERNAME = "somebody";
    public static final String PASSWORD = "1234Password!";
    public static String IDENTITY_ID;
    public static final String NEW_PASSWORD = "new1234Password!";
    public static final int THROTTLED_DELAY = 5000;

    // Populated from awsconfiguration.json
    static Regions clientRegion = Regions.US_WEST_2;
    static String userPoolId;
    static String identityPoolId;

    Context appContext;
    AWSMobileClient auth;
    UserStateListener listener;
    String username;

    @BeforeClass
    public static void beforeClass() throws Exception {
        Context appContext = InstrumentationRegistry.getTargetContext();

        final CountDownLatch latch = new CountDownLatch(1);
        AWSMobileClient.getInstance().initialize(appContext, new Callback<UserStateDetails>() {
            @Override
            public void onResult(UserStateDetails result) {
                latch.countDown();
            }

            @Override
            public void onError(Exception e) {
                latch.countDown();
            }
        });
        latch.await();

        final AWSConfiguration awsConfiguration = AWSMobileClient.getInstance().getConfiguration();

        JSONObject userPoolConfig = awsConfiguration.optJsonObject("CognitoUserPool");
        assertNotNull(userPoolConfig);
        clientRegion = Regions.fromName(userPoolConfig.getString("Region"));
        userPoolId = userPoolConfig.getString("PoolId");

        JSONObject identityPoolConfig =
                awsConfiguration.optJsonObject("CredentialsProvider").getJSONObject(
                        "CognitoIdentity").getJSONObject("Default");
        assertNotNull(identityPoolConfig);
        identityPoolId = identityPoolConfig.getString("PoolId");
    }

    @Before
    public void before() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
        auth = AWSMobileClient.getInstance();
        auth.signOut();

        username = "testUser" + System.currentTimeMillis() + new Random().nextInt();
    }

    @After
    public void after() {
        auth.removeUserStateListener(listener);
        auth.listeners.clear();
        auth.signOut();
    }

    @Test
    public void useAppContext() throws Exception {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        final AWSConfiguration awsConfiguration = new AWSConfiguration(appContext);

        assertNotNull(awsConfiguration.optJsonObject("CognitoUserPool"));
        assertEquals("us-west-2", awsConfiguration.optJsonObject("CognitoUserPool").getString("Region"));

        assertEquals("com.amazonaws.mobile.client.test", appContext.getPackageName());
    }

    @Test
    public void testGetConfiguration() throws JSONException {
        final AWSConfiguration awsConfiguration = AWSMobileClient.getInstance().getConfiguration();

        assertNotNull(awsConfiguration.optJsonObject("CognitoUserPool"));
        try {
            assertEquals("us-west-2", awsConfiguration.optJsonObject("CognitoUserPool").getString("Region"));
        } catch (JSONException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testNetworkExceptionPropagation() throws Exception {
        final AWSKeyValueStore awsKeyValueStore = new AWSKeyValueStore(appContext,
                AWSMobileClient.SHARED_PREFERENCES_KEY,
                true);
        awsKeyValueStore.put(AWSMobileClient.PROVIDER_KEY, AWSMobileClient.getInstance().getLoginKey());
        awsKeyValueStore.put(AWSMobileClient.TOKEN_KEY, getValidJWT(-3600L));
        awsKeyValueStore.put(AWSMobileClient.IDENTITY_ID_KEY, "");
        writeUserpoolsTokens(appContext, auth.getConfiguration().optJsonObject("CognitoUserPool").getString("AppClientId"), USERNAME, -3600L);
        Field f1 = CognitoUserPool.class.getDeclaredField("client");
        f1.setAccessible(true);
        f1.set(auth.userpool, mockLowLevel);
        try {
            final Map<String, String> userAttributes = auth.getUserAttributes();
        } catch (Exception e) {
            assertTrue("Deep cause should be network exception", e.getCause().getCause() instanceof UnknownHostException);
        }
    }

    AmazonCognitoIdentityProvider mockLowLevel = new AbstractAmazonCognitoIdentityProvider() {
        @Override
        public InitiateAuthResult initiateAuth(InitiateAuthRequest initiateAuthRequest) throws AmazonClientException, AmazonServiceException {
            throw new AmazonClientException("Unable to execute HTTP request: Unable to resolve " +
                    "host \"cognito-idp.us-west-2.amazonaws.com\": No address associated with " +
                    "hostname", new UnknownHostException("Unable to resolve host \"cognito-idp" +
                    ".us-west-2.amazonaws.com\": No address associated with hostname"));
        }
    };

}
