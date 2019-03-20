import requests
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
import uuid
import base64
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from collections import namedtuple
import enum
import time

GATEWAY_URL = 'https://kic.lgthinq.com:46030/api/common/gatewayUriList'
APP_KEY = 'wideq'
SECURITY_KEY = 'nuts_securitykey'
DATA_ROOT = 'lgedmRoot'
COUNTRY = 'US'
LANGUAGE = 'en-US'
SVC_CODE = 'SVC202'
CLIENT_ID = 'LGAO221A02'
OAUTH_SECRET_KEY = 'c053c2a6ddeb7ad97cb0eed0dcb31cf8'
OAUTH_CLIENT_KEY = 'LGAO221A02'
DATE_FORMAT = '%a, %d %b %Y %H:%M:%S +0000'

"""DRYER STATE"""
STATE_DRYER_POWER_OFF  = "N/A"
STATE_DRYER_OFF  = "Power Off"
STATE_DRYER_DRYING  = "Drying"
STATE_DRYER_SMART_DIAGNOSIS  = "Smart Diagnosis"
STATE_DRYER_WRINKLE_CARE  = "Wrinkle Care"
STATE_DRYER_INITIAL  = "Initial"
STATE_DRYER_RUNNING  = "Running"
STATE_DRYER_PAUSE  = "Pause"
STATE_DRYER_COOLING = "Cooling"
STATE_DRYER_END  = "End"
STATE_DRYER_ERROR  = "Error"

STATE_DRYER_PROCESS_DETECTING  = "Dryer process detecting"
STATE_DRYER_PROCESS_STEAM  = "Dryer process steam"
STATE_DRYER_PROCESS_DRY  = "Dryer process dry"
STATE_DRYER_PROCESS_COOLING  = "Dryer process cooling"
STATE_DRYER_PROCESS_ANTI_CREASE  = "Dryer process anti crease"
STATE_DRYER_PROCESS_END  = "Dryer process end"

STATE_DRY_LEVEL_IRON  = "Iron"
STATE_DRY_LEVEL_CUPBOARD  = "Cupboard"
STATE_DRY_LEVEL_EXTRA  = "Extra"
STATE_DRY_LEVEL_DAMP  = "Damp"
STATE_DRY_LEVEL_LESS  = "Less"
STATE_DRY_LEVEL_MORE  = "More"
STATE_DRY_LEVEL_NORMAL = "Normal"
STATE_DRY_LEVEL_VERY = "Very"

STATE_DRY_TEMP_ULTRA_LOW = "Ultra Low"
STATE_DRY_TEMP_LOW = "Low"
STATE_DRY_TEMP_MEDIUM = "Medium"
STATE_DRY_TEMP_MID_HIGH = "Mid High"
STATE_DRY_TEMP_HIGH = "High"

STATE_ECOHYBRID_ECO  = "Ecohybrid eco"
STATE_ECOHYBRID_NORMAL  = "Ecohybrid normal"
STATE_ECOHYBRID_TURBO  = "Ecohybrid turbo"

STATE_COURSE_COTTON_SOFT = "Cotton Soft"
STATE_COURSE_BULKY_ITEM = "Bulky Item"
STATE_COURSE_EASY_CARE = "Easy Care"
STATE_COURSE_COTTON = "Cotton"
STATE_COURSE_SPORTS_WEAR = "Sports Wear"
STATE_COURSE_QUICK_DRY = "Quick Dry"
STATE_COURSE_WOOL = "Wool"
STATE_COURSE_RACK_DRY = "Rack Dry"
STATE_COURSE_COOL_AIR = "Cool Air"
STATE_COURSE_WARM_AIR = "Warm Air"
STATE_COURSE_BEDDING_BRUSH = "Bedding Brush"
STATE_COURSE_STERILIZATION = "Sterilization"
STATE_COURSE_POWER = "Power"
STATE_COURSE_REFRESH = "Refresh"
STATE_COURSE_NORMAL = "Normal"
STATE_COURSE_SPEED_DRY = "Speed Dry"
STATE_COURSE_HEAVY_DUTY = "Heavy Duty"
STATE_COURSE_NORMAL = "Normal"
STATE_COURSE_PERM_PRESS = "Permenant Press"
STATE_COURSE_DELICATES = "Delicates"
STATE_COURSE_BEDDING = "Bedding"
STATE_COURSE_AIR_DRY = "Air Dry"
STATE_COURSE_TIME_DRY = "Time Dry"

STATE_SMARTCOURSE_GYM_CLOTHES  = "Smartcourse gym clothes"
STATE_SMARTCOURSE_RAINY_SEASON  = "Smartcourse rainy season"
STATE_SMARTCOURSE_DEODORIZATION  = "Smartcourse deodorization"
STATE_SMARTCOURSE_SMALL_LOAD  = "Smartcourse small load"
STATE_SMARTCOURSE_LINGERIE  = "Smartcourse lingerie"
STATE_SMARTCOURSE_EASY_IRON  = "Smartcourse easy iron"
STATE_SMARTCOURSE_SUPER_DRY  = "Smartcourse super dry"
STATE_SMARTCOURSE_ECONOMIC_DRY  = "Smartcourse economic dry"
STATE_SMARTCOURSE_BIG_SIZE_ITEM  = "Smartcourse big size item"
STATE_SMARTCOURSE_MINIMIZE_WRINKLES  = "Smartcourse minimize wrinkles"
STATE_SMARTCOURSE_FULL_SIZE_LOAD  = "Smartcourse full size load"
STATE_SMARTCOURSE_JEAN  = "Smartcourse jean"

STATE_ERROR_DOOR  = "Error door"
STATE_ERROR_DRAINMOTOR  = "Error drainmotor"
STATE_ERROR_LE1  = "Error le1"
STATE_ERROR_TE1  = "Error te1"
STATE_ERROR_TE2  = "Error te2"
STATE_ERROR_F1  = "Error f1"
STATE_ERROR_LE2  = "Error le2"
STATE_ERROR_AE  = "Error ae"
STATE_ERROR_dE4  = "Error de4"
STATE_ERROR_NOFILTER  = "Error nofilter"
STATE_ERROR_EMPTYWATER  = "Error emptywater"
STATE_ERROR_CE1  = "Error ce1"
STATE_NO_ERROR  = "No Error"

STATE_OPTIONITEM_ON  = "On"
STATE_OPTIONITEM_OFF  = "Off"

"""WASHER STATE"""
STATE_WASHER_OFF  = "Power Off"
STATE_WASHER_POWER_OFF  = "N/A"
STATE_WASHER_INITIAL  = "Initial"
STATE_WASHER_PAUSE  = "Pause"
STATE_WASHER_ERROR_AUTO_OFF  = "Error auto off"
STATE_WASHER_RESERVE  = "Reserve"
STATE_WASHER_DETECTING  = "Detecting"
STATE_WASHER_ADD_DRAIN  = "Add drain"
STATE_WASHER_DETERGENT_AMOUT  = "Detergent amout"
STATE_WASHER_RUNNING  = "Running"
STATE_WASHER_PREWASH  = "Pre-wash"
STATE_WASHER_RINSING  = "Rinsing"
STATE_WASHER_RINSE_HOLD  = "Rinse Hold"
STATE_WASHER_SPINNING  = "Spinning"
STATE_WASHER_SOAK  = "Soaking"
STATE_WASHER_COMPLETE  = "Complete"
STATE_WASHER_FIRMWARE  = "Firmware"
STATE_WASHER_SMART_DIAGNOSIS  = "Smart Diagnosis"
STATE_WASHER_DRYING  = "Drying"
STATE_WASHER_END  = "End"
STATE_WASHER_FRESHCARE  = "Freshcare"
STATE_WASHER_TCL_ALARM_NORMAL  = "TCL alarm normal"
STATE_WASHER_FROZEN_PREVENT_INITIAL  = "Frozen prevent initial"
STATE_WASHER_FROZEN_PREVENT_RUNNING  = "Frozen prevent running"
STATE_WASHER_FROZEN_PREVENT_PAUSE  = "Frozen prevent pause"
STATE_WASHER_ERROR  = "Error"

STATE_WASHER_SOIL_LIGHT  = "Light"
STATE_WASHER_SOIL_LIGHT_NORMAL  = "Light Normal"
STATE_WASHER_SOIL_NORMAL  = "Normal"
STATE_WASHER_SOIL_NORMAL_HEAVY  = "Normal Heavy"
STATE_WASHER_SOIL_HEAVY  = "Heavy"
STATE_WASHER_SOIL_PRE_WASH  = "Pre-wash"
STATE_WASHER_SOIL_SOAKING  = "Soaking"

STATE_WASHER_WATERTEMP_TAP_COLD  = "Tap Cold"
STATE_WASHER_WATERTEMP_COLD  = "Cold"
STATE_WASHER_WATERTEMP_SEMI_WARM  = "Semi-Warm"
STATE_WASHER_WATERTEMP_WARM  = "Warm"
STATE_WASHER_WATERTEMP_HOT  = "Hot"
STATE_WASHER_WATERTEMP_EXTRA_HOT  = "Extra Hot"
STATE_WASHER_WATERTEMP_30 = '30'
STATE_WASHER_WATERTEMP_40 = '40'
STATE_WASHER_WATERTEMP_60 = '60'
STATE_WASHER_WATERTEMP_95 = '95'

STATE_WASHER_SPINSPEED_NO_SELET  = "No select"
STATE_WASHER_SPINSPEED_EXTRA_LOW  = "Extra Low"
STATE_WASHER_SPINSPEED_LOW  = "Low"
STATE_WASHER_SPINSPEED_MEDIUM  = "Medium"
STATE_WASHER_SPINSPEED_HIGH  = "High"
STATE_WASHER_SPINSPEED_EXTRA_HIGH  = "Extra High"

STATE_WASHER_RINSECOUNT_1  = "Washer rinsecount 1"
STATE_WASHER_RINSECOUNT_2  = "Washer rinsecount 2"
STATE_WASHER_RINSECOUNT_3  = "Washer rinsecount 3"
STATE_WASHER_RINSECOUNT_4  = "Washer rinsecount 4"
STATE_WASHER_RINSECOUNT_5  = "Washer rinsecount 5"

STATE_WASHER_DRYLEVEL_WIND  = "Washer drylevel wind"
STATE_WASHER_DRYLEVEL_TURBO  = "Washer drylevel turbo"
STATE_WASHER_DRYLEVEL_TIME_30  = "Washer drylevel time 30"
STATE_WASHER_DRYLEVEL_TIME_60  = "Washer drylevel time 60"
STATE_WASHER_DRYLEVEL_TIME_90  = "Washer drylevel time 90"
STATE_WASHER_DRYLEVEL_TIME_120  = "Washer drylevel time 120"
STATE_WASHER_DRYLEVEL_TIME_150  = "Washer drylevel time 150"

STATE_WASHER_NO_ERROR  = "No Error"
STATE_WASHER_ERROR_dE2  = "Washer error de2"
STATE_WASHER_ERROR_IE  = "Washer error ie"
STATE_WASHER_ERROR_OE  = "Washer error oe"
STATE_WASHER_ERROR_UE  = "Washer error ue"
STATE_WASHER_ERROR_FE  = "Washer error fe"
STATE_WASHER_ERROR_PE  = "Washer error pe"
STATE_WASHER_ERROR_LE  = "Washer error le"
STATE_WASHER_ERROR_tE  = "Washer error te"
STATE_WASHER_ERROR_dHE  = "Washer error dhe"
STATE_WASHER_ERROR_CE  = "Washer error ce"
STATE_WASHER_ERROR_PF  = "Washer error pf"
STATE_WASHER_ERROR_FF  = "Washer error ff"
STATE_WASHER_ERROR_dCE  = "Washer error dce"
STATE_WASHER_ERROR_EE  = "Washer error ee"
STATE_WASHER_ERROR_PS  = "Washer error ps"
STATE_WASHER_ERROR_dE1  = "Washer error de1"
STATE_WASHER_ERROR_LOE  = "Washer error loe"

STATE_WASHER_APCOURSE_COTTON  = "Washer apcourse cotton"
STATE_WASHER_APCOURSE_SPEEDWASH_DRY  = "Washer apcourse speedwash dry"
STATE_WASHER_APCOURSE_SPEEDWASH  = "Washer apcourse speedwash"
STATE_WASHER_APCOURSE_SINGLE_SHIRT_DRY  = "Washer apcourse single shirt dry"
STATE_WASHER_APCOURSE_RINSESPIN  = "Washer apcourse rinsespin"
STATE_WASHER_APCOURSE_SPEEDBOIL  = "Washer apcourse speedboil"
STATE_WASHER_APCOURSE_ALLERGYCARE  = "Washer apcourse allergycare"
STATE_WASHER_APCOURSE_STEAMCLEANING  = "Washer apcourse steamcleaning"
STATE_WASHER_APCOURSE_BABYWEAR  = "Washer apcourse babywear"
STATE_WASHER_APCOURSE_BLANKET_ROB  = "Washer apcourse blanket rob"
STATE_WASHER_APCOURSE_UTILITY  = "Washer apcourse utility"
STATE_WASHER_APCOURSE_BLANKET  = "Washer apcourse blanket"
STATE_WASHER_APCOURSE_LINGERIE_WOOL  = "Washer apcourse lingerie wool"
STATE_WASHER_APCOURSE_COLDWASH  = "Washer apcourse coldwash"
STATE_WASHER_APCOURSE_TUBCLEAN_SANITARY  = "Washer apcourse tubclean sanitary"
STATE_WASHER_APCOURSE_DOWNLOAD_COUSE  = "Washer apcourse download couse"

STATE_WASHER_COURSE_NORMAL = "Normal"
STATE_WASHER_COURSE_HEAVY_DUTY = "Heavy Duty"
STATE_WASHER_COURSE_DELICATES = "Delicates"
STATE_WASHER_COURSE_WATER_PROOF = "Waterproof"
STATE_WASHER_COURSE_SPEED_WASH = "Speed Wash"
STATE_WASHER_COURSE_BEDDING = "Bedding"
STATE_WASHER_COURSE_TUB_CLEAN = "Tub Clean"
STATE_WASHER_COURSE_RINSE_SPIN = "Rinse Spin"
STATE_WASHER_COURSE_SPIN_ONLY = "Spin Only"
STATE_WASHER_COURSE_PREWASH_PLUS = "Prewash Plus"

STATE_WASHER_SMARTCOURSE_SILENT  = "Washer smartcourse silent"
STATE_WASHER_SMARTCOURSE_SMALL_LOAD  = "Washer smartcourse small load"
STATE_WASHER_SMARTCOURSE_SKIN_CARE  = "Washer smartcourse skin care"
STATE_WASHER_SMARTCOURSE_RAINY_SEASON  = "Washer smartcourse rainy season"
STATE_WASHER_SMARTCOURSE_SWEAT_STAIN  = "Washer smartcourse sweat stain"
STATE_WASHER_SMARTCOURSE_SINGLE_GARMENT  = "Washer smartcourse single garment"
STATE_WASHER_SMARTCOURSE_SCHOOL_UNIFORM  = "Washer smartcourse school uniform"
STATE_WASHER_SMARTCOURSE_STATIC_REMOVAL  = "Washer smartcourse static removal"
STATE_WASHER_SMARTCOURSE_COLOR_CARE  = "Washer smartcourse color care"
STATE_WASHER_SMARTCOURSE_SPIN_ONLY  = "Washer smartcourse spin only"
STATE_WASHER_SMARTCOURSE_DEODORIZATION  = "Washer smartcourse deodorization"
STATE_WASHER_SMARTCOURSE_BEDDING_CARE  = "Washer smartcourse bedding care"
STATE_WASHER_SMARTCOURSE_CLOTH_CARE  = "Washer smartcourse cloth care"
STATE_WASHER_SMARTCOURSE_SMART_RINSE  = "Washer smartcourse smart rinse"
STATE_WASHER_SMARTCOURSE_ECO_WASH  = "Washer smartcourse eco wash"

STATE_WASHER_TERM_NO_SELECT  = "N/A"

STATE_WASHER_OPTIONITEM_ON  = "On"
STATE_WASHER_OPTIONITEM_OFF  = "Off"

def gen_uuid():
    return str(uuid.uuid4())


def oauth2_signature(message, secret):
    """Get the base64-encoded SHA-1 HMAC digest of a string, as used in
    OAauth2 request signatures.

    Both the `secret` and `message` are given as text strings. We use
    their UTF-8 equivalents.
    """

    secret_bytes = secret.encode('utf8')
    hashed = hmac.new(secret_bytes, message.encode('utf8'), hashlib.sha1)
    digest = hashed.digest()
    return base64.b64encode(digest)


def as_list(obj):
    """Wrap non-lists in lists.

    If `obj` is a list, return it unchanged. Otherwise, return a
    single-element list containing it.
    """

    if isinstance(obj, list):
        return obj
    else:
        return [obj]


class APIError(Exception):
    """An error reported by the API."""

    def __init__(self, code, message):
        self.code = code
        self.message = message


class NotLoggedInError(APIError):
    """The session is not valid or expired."""

    def __init__(self):
        pass


class TokenError(APIError):
    """An authentication token was rejected."""

    def __init__(self):
        pass


class MonitorError(APIError):
    """Monitoring a device failed, possibly because the monitoring
    session failed and needs to be restarted.
    """

    def __init__(self, device_id, code):
        self.device_id = device_id
        self.code = code

class NotConnectError(APIError):
    """The session is not valid or expired."""

    def __init__(self):
        pass


def lgedm_post(url, data=None, access_token=None, session_id=None):
    """Make an HTTP request in the format used by the API servers.

    In this format, the request POST data sent as JSON under a special
    key; authentication sent in headers. Return the JSON data extracted
    from the response.

    The `access_token` and `session_id` are required for most normal,
    authenticated requests. They are not required, for example, to load
    the gateway server data or to start a session.
    """

    headers = {
        'x-thinq-application-key': APP_KEY,
        'x-thinq-security-key': SECURITY_KEY,
        'Accept': 'application/json',
    }
    if access_token:
        headers['x-thinq-token'] = access_token
    if session_id:
        headers['x-thinq-jsessionId'] = session_id

    res = requests.post(url, json={DATA_ROOT: data}, headers=headers)
    out = res.json()[DATA_ROOT]

    # Check for API errors.
    if 'returnCd' in out:
        code = out['returnCd']
        if code != '0000':
            message = out['returnMsg']
            if code == "0102":
                raise NotLoggedInError()
            elif code == "0106":
                raise NotConnectError()
            elif code == "0010":
                return out
            else:
                raise APIError(code, message)


    return out


def gateway_info():
    """Load information about the hosts to use for API interaction.
    """

    return lgedm_post(
        GATEWAY_URL,
        {'countryCode': COUNTRY, 'langCode': LANGUAGE},
    )


def oauth_url(auth_base):
    """Construct the URL for users to log in (in a browser) to start an
    authenticated session.
    """

    url = urljoin(auth_base, 'login/sign_in')
    query = urlencode({
        'country': COUNTRY,
        'language': LANGUAGE,
        'svcCode': SVC_CODE,
        'authSvr': 'oauth2',
        'client_id': CLIENT_ID,
        'division': 'ha',
        'grant_type': 'password',
    })
    return '{}?{}'.format(url, query)


def parse_oauth_callback(url):
    """Parse the URL to which an OAuth login redirected to obtain two
    tokens: an access token for API credentials, and a refresh token for
    getting updated access tokens.
    """

    params = parse_qs(urlparse(url).query)
    return params['access_token'][0], params['refresh_token'][0]


def login(api_root, access_token):
    """Use an access token to log into the API and obtain a session and
    return information about the session.
    """

    url = urljoin(api_root + '/', 'member/login')
    data = {
        'countryCode': COUNTRY,
        'langCode': LANGUAGE,
        'loginType': 'EMP',
        'token': access_token,
    }
    return lgedm_post(url, data)


def refresh_auth(oauth_root, refresh_token):
    """Get a new access_token using a refresh_token.

    May raise a `TokenError`.
    """

    token_url = urljoin(oauth_root, '/oauth2/token')
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }

    # The timestamp for labeling OAuth requests can be obtained
    # through a request to the date/time endpoint:
    # https://us.lgeapi.com/datetime
    # But we can also just generate a timestamp.
    timestamp = datetime.utcnow().strftime(DATE_FORMAT)

    # The signature for the requests is on a string consisting of two
    # parts: (1) a fake request URL containing the refresh token, and (2)
    # the timestamp.
    req_url = ('/oauth2/token?grant_type=refresh_token&refresh_token=' +
               refresh_token)
    sig = oauth2_signature('{}\n{}'.format(req_url, timestamp),
                           OAUTH_SECRET_KEY)

    headers = {
        'lgemp-x-app-key': OAUTH_CLIENT_KEY,
        'lgemp-x-signature': sig,
        'lgemp-x-date': timestamp,
        'Accept': 'application/json',
    }

    res = requests.post(token_url, data=data, headers=headers)
    res_data = res.json()

    if res_data['status'] != 1:
        raise TokenError()
    return res_data['access_token']


class Gateway(object):
    def __init__(self, auth_base, api_root, oauth_root):
        self.auth_base = auth_base
        self.api_root = api_root
        self.oauth_root = oauth_root

    @classmethod
    def discover(cls):
        gw = gateway_info()
        return cls(gw['empUri'], gw['thinqUri'], gw['oauthUri'])

    def oauth_url(self):
        return oauth_url(self.auth_base)


class Auth(object):
    def __init__(self, gateway, access_token, refresh_token):
        self.gateway = gateway
        self.access_token = access_token
        self.refresh_token = refresh_token

    @classmethod
    def from_url(cls, gateway, url):
        """Create an authentication using an OAuth callback URL.
        """

        access_token, refresh_token = parse_oauth_callback(url)
        return cls(gateway, access_token, refresh_token)

    def start_session(self):
        """Start an API session for the logged-in user. Return the
        Session object and a list of the user's devices.
        """

        session_info = login(self.gateway.api_root, self.access_token)
        session_id = session_info['jsessionId']
        return Session(self, session_id), as_list(session_info['item'])

    def refresh(self):
        """Refresh the authentication, returning a new Auth object.
        """

        new_access_token = refresh_auth(self.gateway.oauth_root,
                                        self.refresh_token)
        return Auth(self.gateway, new_access_token, self.refresh_token)


class Session(object):
    def __init__(self, auth, session_id):
        self.auth = auth
        self.session_id = session_id

    def post(self, path, data=None):
        """Make a POST request to the API server.

        This is like `lgedm_post`, but it pulls the context for the
        request from an active Session.
        """

        url = urljoin(self.auth.gateway.api_root + '/', path)
        return lgedm_post(url, data, self.auth.access_token, self.session_id)

    def get_devices(self):
        """Get a list of devices associated with the user's account.

        Return a list of dicts with information about the devices.
        """

        return as_list(self.post('device/deviceList')['item'])

    def monitor_start(self, device_id):
        """Begin monitoring a device's status.

        Return a "work ID" that can be used to retrieve the result of
        monitoring.
        """

        res = self.post('rti/rtiMon', {
            'cmd': 'Mon',
            'cmdOpt': 'Start',
            'deviceId': device_id,
            'workId': gen_uuid(),
        })
        return res['workId']

    def monitor_poll(self, device_id, work_id):
        """Get the result of a monitoring task.

        `work_id` is a string ID retrieved from `monitor_start`. Return
        a status result, which is a bytestring, or None if the
        monitoring is not yet ready.

        May raise a `MonitorError`, in which case the right course of
        action is probably to restart the monitoring task.
        """

        work_list = [{'deviceId': device_id, 'workId': work_id}]
        res = self.post('rti/rtiResult', {'workList': work_list})['workList']

        # The return data may or may not be present, depending on the
        # monitoring task status.
        if 'returnData' in res:
            # The main response payload is base64-encoded binary data in
            # the `returnData` field. This sometimes contains JSON data
            # and sometimes other binary data.
            return base64.b64decode(res['returnData'])
        else:
            return None
         # Check for errors.
        code = res.get('returnCode')  # returnCode can be missing.
        if code != '0000':
            raise MonitorError(device_id, code)


    def monitor_stop(self, device_id, work_id):
        """Stop monitoring a device."""

        self.post('rti/rtiMon', {
            'cmd': 'Mon',
            'cmdOpt': 'Stop',
            'deviceId': device_id,
            'workId': work_id,
        })

    def set_device_operation(self, device_id, values):
        """Control a device's settings.

        `values` is a key/value map containing the settings to update.
        """

        return self.post('rti/rtiControl', {
            'cmd': 'Control',
            'cmdOpt': 'Operation',
            'value': values,
            'deviceId': device_id,
            'workId': gen_uuid(),
            'data': '',
        })

    def set_device_controls(self, device_id, values):
        """Control a device's settings.

        `values` is a key/value map containing the settings to update.
        """

        return self.post('rti/rtiControl', {
            'cmd': 'Control',
            'cmdOpt': 'Set',
            'value': values,
            'deviceId': device_id,
            'workId': gen_uuid(),
            'data': '',
        })

    def get_device_config(self, device_id, key, category='Config'):
        """Get a device configuration option.

        The `category` string should probably either be "Config" or
        "Control"; the right choice appears to depend on the key.
        """

        res = self.post('rti/rtiControl', {
            'cmd': category,
            'cmdOpt': 'Get',
            'value': key,
            'deviceId': device_id,
            'workId': gen_uuid(),
            'data': '',
        })
        return res['returnData']

    def delete_permission(self, device_id):
        self.post('rti/delControlPermission', {
            'deviceId': device_id,
        })

    def get_power_data(self, device_id, period):
        res = self.post('aircon/inquiryPowerData', {
            'deviceId': device_id,
            'period': period,
        })
        code = res.get('returnCd')  # returnCode can be missing.
        if code == '0000':
            return res['powerData']
        elif code == '0010':
            return '0'
        else:
            raise MonitorError(device_id, code)

    def get_water_usage(self, device_id, typeCode, sDate, eDate):
        res = self.post('rms/inquiryWaterConsumptionInfo', {
            'deviceId': device_id,
            'type': typeCode,
            'startDate': sDate,
            'endDate': eDate,
        })
        
        code = res.get('returnCd')  # returnCode can be missing.
        if code != '0000':
            raise MonitorError(device_id, code)
        else:
            return res['item']
            
    def get_outdoor_weather(self, area):
        res = self.post('weather/weatherNewsData',{
            'area': area
        })
        code = res.get('returnCd')  # returnCode can be missing.
        if code != '0000':
            raise MonitorError(device_id, code)
        else:
            return res

        
class Monitor(object):
    """A monitoring task for a device.
        
        This task is robust to some API-level failures. If the monitoring
        task expires, it attempts to start a new one automatically. This
        makes one `Monitor` object suitable for long-term monitoring.
        """
    
    def __init__(self, session, device_id):
        self.session = session
        self.device_id = device_id
    
    def start(self):
        self.work_id = self.session.monitor_start(self.device_id)
    
    def stop(self):
        self.session.monitor_stop(self.device_id, self.work_id)
    
    def poll(self):
        """Get the current status data (a bytestring) or None if the
            device is not yet ready.
            """
        self.work_id = self.session.monitor_start(self.device_id)
        try:
            return self.session.monitor_poll(self.device_id, self.work_id)
        except MonitorError:
            # Try to restart the task.
            self.stop()
            self.start()
            return None


    @staticmethod
    def decode_json(data):
        """Decode a bytestring that encodes JSON status data."""
        
        return json.loads(data.decode('utf8'))
    
    def poll_json(self):
        """For devices where status is reported via JSON data, get the
            decoded status result (or None if status is not available).
            """
        
        data = self.poll()
        return self.decode_json(data) if data else None
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, type, value, tb):
        self.stop()


class Client(object):
    """A higher-level API wrapper that provides a session more easily
        and allows serialization of state.
        """
    
    def __init__(self, gateway=None, auth=None, session=None):
        # The three steps required to get access to call the API.
        self._gateway = gateway
        self._auth = auth
        self._session = session
        
        # The last list of devices we got from the server. This is the
        # raw JSON list data describing the devices.
        self._devices = None
        
        # Cached model info data. This is a mapping from URLs to JSON
        # responses.
        self._model_info = {}
    
    @property
    def gateway(self):
        if not self._gateway:
            self._gateway = Gateway.discover()
        return self._gateway
    
    @property
    def auth(self):
        if not self._auth:
            assert False, "unauthenticated"
        return self._auth
    
    @property
    def session(self):
        if not self._session:
            self._session, self._devices = self.auth.start_session()
        return self._session
    
    @property
    def devices(self):
        """DeviceInfo objects describing the user's devices.
            """
        
        if not self._devices:
            self._devices = self.session.get_devices()
        return (DeviceInfo(d) for d in self._devices)
    
    def get_device(self, device_id):
        """Look up a DeviceInfo object by device ID.
            
            Return None if the device does not exist.
            """
        
        for device in self.devices:
            if device.id == device_id:
                return device
        return None
    
    @classmethod
    def load(cls, state):
        """Load a client from serialized state.
            """
        
        client = cls()
        
        if 'gateway' in state:
            data = state['gateway']
            client._gateway = Gateway(
            data['auth_base'], data['api_root'], data['oauth_root']
            )
        
        if 'auth' in state:
            data = state['auth']
            client._auth = Auth(
            client.gateway, data['access_token'], data['refresh_token']
            )
        
        if 'session' in state:
            client._session = Session(client.auth, state['session'])
                
        if 'model_info' in state:
            client._model_info = state['model_info']
                
        return client

    def dump(self):
        """Serialize the client state."""
        
        out = {
            'model_info': self._model_info,
        }
        
        if self._gateway:
            out['gateway'] = {
                'auth_base': self._gateway.auth_base,
                'api_root': self._gateway.api_root,
                'oauth_root': self._gateway.oauth_root,
        }
        
        if self._auth:
            out['auth'] = {
                'access_token': self._auth.access_token,
                'refresh_token': self._auth.refresh_token,
        }

        if self._session:
            out['session'] = self._session.session_id

        return out
    
    def refresh(self):
        self._auth = self.auth.refresh()
        self._session, self._devices = self.auth.start_session()
    
    @classmethod
    def from_token(cls, refresh_token):
        """Construct a client using just a refresh token.
            
            This allows simpler state storage (e.g., for human-written
            configuration) but it is a little less efficient because we need
            to reload the gateway servers and restart the session.
            """
        
        client = cls()
        client._auth = Auth(client.gateway, None, refresh_token)
        client.refresh()
        return client
    
    def model_info(self, device):
        """For a DeviceInfo object, get a ModelInfo object describing
            the model's capabilities.
            """
        url = device.model_info_url
        if url not in self._model_info:
            self._model_info[url] = device.load_model_info()
        return ModelInfo(self._model_info[url])


class DeviceType(enum.Enum):
    """The category of device."""

    WASHER = 201
    DRYER = 202


class DeviceInfo(object):
    """Details about a user's device.
        
    This is populated from a JSON dictionary provided by the API.
    """
    
    def __init__(self, data):
        self.data = data
    
    @property
    def model_id(self):
        return self.data['modelNm']
    
    @property
    def id(self):
        return self.data['deviceId']
    
    @property
    def model_info_url(self):
        return self.data['modelJsonUrl']
    
    @property
    def name(self):
        return self.data['alias']

    @property
    def macaddress(self):
        return self.data['macAddress']

    @property
    def model_name(self):
        return self.data['modelNm']

    @property
    def type(self):
        """The kind of device, as a `DeviceType` value."""
        
        return DeviceType(self.data['deviceType'])
    
    def load_model_info(self):
        """Load JSON data describing the model's capabilities.
        """
        return requests.get(self.model_info_url).json()


EnumValue = namedtuple('EnumValue', ['options'])
RangeValue = namedtuple('RangeValue', ['min', 'max', 'step'])
BitValue = namedtuple('BitValue', ['options'])
ReferenceValue = namedtuple('ReferenceValue', ['reference'])


class ModelInfo(object):
    """A description of a device model's capabilities.
        """
    
    def __init__(self, data):
        self.data = data
    
    @property
    def model_type(self):
        return self.data['Info']['modelType']

    def value_type(self, name):
        if name in self.data['Value']:
            return self.data['Value'][name]['type']
        else:
            return None

    def value(self, name):
        """Look up information about a value.
        
        Return either an `EnumValue` or a `RangeValue`.
        """
        d = self.data['Value'][name]
        if d['type'] in ('Enum', 'enum'):
            return EnumValue(d['option'])
        elif d['type'] == 'Range':
            return RangeValue(d['option']['min'], d['option']['max'], d['option']['step'])
        elif d['type'] == 'Bit':
            bit_values = {}
            for bit in d['option']:
                bit_values[bit['startbit']] = {
                'value' : bit['value'],
                'length' : bit['length'],
                }
            return BitValue(
                    bit_values
                    )
        elif d['type'] == 'Reference':
            ref =  d['option'][0]
            return ReferenceValue(
                    self.data[ref]
                    )
        elif d['type'] == 'Boolean':
            return EnumValue({'0': 'False', '1' : 'True'})
        elif d['type'] == 'String':
            pass 
        else:
            assert False, "unsupported value type {}".format(d['type'])


    def default(self, name):
        """Get the default value, if it exists, for a given value.
        """
            
        return self.data['Value'][name]['default']

    def option_item(self, name):
        """Get the default value, if it exists, for a given value.
        """
            
        options = self.value(name).options
        return options

    def enum_value(self, key, name):
        """Look up the encoded value for a friendly enum name.
        """
        
        options = self.value(key).options
        options_inv = {v: k for k, v in options.items()}  # Invert the map.
        return options_inv[name]

    def enum_name(self, key, value):
        """Look up the friendly enum name for an encoded value.
        """
        if not self.value_type(key):
            return str(value)
                
        options = self.value(key).options
        return options[value]

    def range_name(self, key):
        """Look up the value of a RangeValue.  Not very useful other than for comprehension
        """
            
        return key
        
    def bit_name(self, key, bit_index, value):
        """Look up the friendly name for an encoded bit value
        """
        if not self.value_type(key):
            return str(value)
        
        options = self.value(key).options
        
        if not self.value_type(options[bit_index]['value']):
            return str(value)
        
        enum_options = self.value(options[bit_index]['value']).options
        return enum_options[value]

    def reference_name(self, key, value):
        """Look up the friendly name for an encoded reference value
        """
        value = str(value)
        if not self.value_type(key):
            return value
                
        reference = self.value(key).reference
                    
        if value in reference:
            comment = reference[value]['_comment']
            return comment if comment else reference[value]['label']
        else:
            return '-'

    @property
    def binary_monitor_data(self):
        """Check that type of monitoring is BINARY(BYTE).
        """
        
        return self.data['Monitoring']['type'] == 'BINARY(BYTE)'
    
    def decode_monitor_binary(self, data):
        """Decode binary encoded status data.
        """
        
        decoded = {}
        for item in self.data['Monitoring']['protocol']:
            key = item['value']
            value = 0
            for v in data[item['startByte']:item['startByte'] + item['length']]:
                value = (value << 8) + v
            decoded[key] = str(value)
        return decoded
    
    def decode_monitor_json(self, data):
        """Decode a bytestring that encodes JSON status data."""
        
        return json.loads(data.decode('utf8'))
    
    def decode_monitor(self, data):
        """Decode  status data."""
        
        if self.binary_monitor_data:
            return self.decode_monitor_binary(data)
        else:
            return self.decode_monitor_json(data)

class Device(object):
    """A higher-level interface to a specific device.
        
    Unlike `DeviceInfo`, which just stores data *about* a device,
    `Device` objects refer to their client and can perform operations
    regarding the device.
    """

    def __init__(self, client, device):
        """Create a wrapper for a `DeviceInfo` object associated with a
        `Client`.
        """
        
        self.client = client
        self.device = device
        self.model = client.model_info(device)

    def _set_operation(self, value):
        """Set a device's operation for a given `value`.
        """
        
        self.client.session.set_device_controls(
            self.device.id,
            value,
            )

    def _set_control(self, key, value):
        """Set a device's control for `key` to `value`.
        """
        
        self.client.session.set_device_controls(
            self.device.id,
            {key: value},
            )

    def _set_control_ac_wdirvstep(self, key1, value1, key2, value2, key3, value3):
        """Set a device's control for `key` to `value`.
        """
        
        self.client.session.set_device_controls(
            self.device.id,
            {key1: value1, key2: value2, key3:value3},
            )


    def _get_config(self, key):
        """Look up a device's configuration for a given value.
            
        The response is parsed as base64-encoded JSON.
        """
        
        data = self.client.session.get_device_config(
               self.device.id,
               key,
        )
        return json.loads(base64.b64decode(data).decode('utf8'))
    
    def _get_control(self, key):
        """Look up a device's control value.
            """
        
        data = self.client.session.get_device_config(
               self.device.id,
                key,
               'Control',
        )

            # The response comes in a funky key/value format: "(key:value)".
        _, value = data[1:-1].split(':')
        return value


    def _delete_permission(self):
        self.client.session.delete_permission(
            self.device.id,
        )

    def _get_power_data(self, sDate, eDate):
        period = 'Day_'+sDate+'T000000Z/'+eDate+'T000000Z'
        data = self.client.session.get_power_data(
               self.device.id,
                period,
        )
        return data

    def _get_water_usage(self, typeCode, sDate, eDate):
        data = self.client.session.get_water_usage(
               self.device.id,
                typeCode,
                sDate,
                eDate,
        )
        return data

"""------------------for Dryer"""
class DRYERSTATE(enum.Enum):
    
    OFF = "@WM_STATE_POWER_OFF_W"
    INITIAL = "@WM_STATE_INITIAL_W"
    RUNNING = "@WM_STATE_RUNNING_W"
    DRYING = "@WM_STATE_DRYING_W"
    COOLING = "@WM_STATE_COOLING_W"
    PAUSE = "@WM_STATE_PAUSE_W"
    END = "@WM_STATE_END_W"
    ERROR = "@WM_STATE_ERROR_W"
    SMART_DIAGNOSIS = "@WM_STATE_SMART_DIAGNOSIS_W"
    WRINKLE_CARE = "@WM_STATE_WRINKLECARE_W"

class DRYERPROCESSSTATE(enum.Enum):
    
    DETECTING = "@WM_STATE_DETECTING_W"
    STEAM = "@WM_STATE_STEAM_W"
    DRY = "@WM_STATE_DRY_W"
    COOLING = "@WM_STATE_COOLING_W"
    ANTI_CREASE = "@WM_STATE_ANTI_CREASE_W"
    END = "@WM_STATE_END_W"

class DRYLEVEL(enum.Enum):

    DAMP = "@WM_DRY27_DRY_LEVEL_DAMP_W"
    LESS = "@WM_DRY27_DRY_LEVEL_LESS_W"
    NORMAL = "@WM_DRY27_DRY_LEVEL_NORMAL_W"
    MORE = "@WM_DRY27_DRY_LEVEL_MORE_W"
    VERY = "@WM_DRY27_DRY_LEVEL_VERY_W"

class TEMPCONTROL(enum.Enum):

    ULTRA_LOW = "@WM_DRY27_TEMP_ULTRA_LOW_W"
    LOW = "@WM_DRY27_TEMP_LOW_W"
    MEDIUM = "@WM_DRY27_TEMP_MEDIUM_W"
    MID_HIGH = "@WM_DRY27_TEMP_MID_HIGH_W"
    HIGH = "@WM_DRY27_TEMP_HIGH_W"
    
class ECOHYBRID(enum.Enum):
    
    ECO = "@WM_DRY24_ECO_HYBRID_ECO_W"
    NORMAL = "@WM_DRY24_ECO_HYBRID_NORMAL_W"
    TURBO = "@WM_DRY24_ECO_HYBRID_TURBO_W"

class DRYERERROR(enum.Enum):
    
    ERROR_DOOR = "@WM_US_DRYER_ERROR_DE_W"
    ERROR_DRAINMOTOR = "@WM_US_DRYER_ERROR_OE_W"
    ERROR_LE1 = "@WM_US_DRYER_ERROR_LE1_W"
    ERROR_TE1 = "@WM_US_DRYER_ERROR_TE1_W"
    ERROR_TE2 = "@WM_US_DRYER_ERROR_TE2_W"
    ERROR_F1 = "@WM_US_DRYER_ERROR_F1_W"
    ERROR_LE2 = "@WM_US_DRYER_ERROR_LE2_W"
    ERROR_AE = "@WM_US_DRYER_ERROR_AE_W"
    ERROR_dE4 = "@WM_WW_FL_ERROR_DE4_W"
    ERROR_NOFILTER = "@WM_US_DRYER_ERROR_NOFILTER_W"
    ERROR_EMPTYWATER = "@WM_US_DRYER_ERROR_EMPTYWATER_W"
    ERROR_CE1 = "@WM_US_DRYER_ERROR_CE1_W"

class DryerDevice(Device):
    
    def monitor_start(self):
        """Start monitoring the device's status."""
        
        self.mon = Monitor(self.client.session, self.device.id)
        self.mon.start()
    
    def monitor_stop(self):
        """Stop monitoring the device's status."""
        
        self.mon.stop()
    
    def delete_permission(self):
        self._delete_permission()
    
    def poll(self):
        """Poll the device's current state.
        
        Monitoring must be started first with `monitor_start`. Return
        either an `ACStatus` object or `None` if the status is not yet
        available.
        """
        
        data = self.mon.poll()
        if data:
            res = self.model.decode_monitor(data)
            """
            with open('/config/wideq/dryer_polled_data.json','w', encoding="utf-8") as dumpfile:
                json.dump(res, dumpfile, ensure_ascii=False, indent="\t")
            """
            return DryerStatus(self, res)
        
        else:
            return None


class DryerStatus(object):
    
    """Higher-level information about an Ref device's current status.
    """
    
    def __init__(self, dryer, data):
        self.dryer = dryer
        self.data = data
    
    def lookup_enum(self, key):
        return self.dryer.model.enum_name(key, self.data[key])
    
    def lookup_reference(self, key):
        return self.dryer.model.reference_name(key, self.data[key])
    
    def lookup_bit(self, key, index):
        bit_value = int(self.data[key])
        bit_index = 2 ** index
        mode = bin(bit_value & bit_index)
        if mode == bin(0):
            return 'OFF'
        else:
            return 'ON'

    @property
    def is_on(self):
        run_state = DRYERSTATE(self.lookup_enum('State'))
        return run_state != DRYERSTATE.OFF
    
    @property
    def run_state(self):
        return DRYERSTATE(self.lookup_enum('State'))
    
    @property
    def pre_state(self):
        return DRYERSTATE(self.lookup_enum('PreState'))
    
    @property
    def remaintime_hour(self):
        return self.data['Remain_Time_H']
    
    @property
    def remaintime_min(self):
        return self.data['Remain_Time_M']
    
    @property
    def initialtime_hour(self):
        return self.data['Initial_Time_H']
    
    @property
    def initialtime_min(self):
        return self.data['Initial_Time_M']

    @property
    def reservetime_hour(self):
        return self.data['Reserve_Time_H']
    
    @property
    def reservetime_min(self):
        return self.data['Reserve_Time_M']

    @property
    def reserveinitialtime_hour(self):
        return self.data['Reserve_Initial_Time_H']

    @property
    def reserveinitialtime_min(self):
        return self.data['Reserve_Initial_Time_M']
    
    @property
    def current_course(self):
        course = self.lookup_reference('Course')
        if course == '-':
            return 'OFF'
        else:
            return course

    @property
    def error_state(self):
        error = self.lookup_reference('Error')
        if error == '-':
            return 'OFF'
        elif error == 'No Error':
            return 'NO_ERROR'
        else:
            return DRYERERROR(error)

    @property
    def drylevel_state(self):
        drylevel = self.lookup_enum('DryLevel')
        if drylevel == '-':
            return 'OFF'
        return DRYLEVEL(drylevel)

    @property
    def tempcontrol_state(self):
        tempcontrol = self.lookup_enum('TempControl')
        if tempcontrol == '-':
            return 'OFF'
        return TEMPCONTROL(tempcontrol)    
    
    @property
    def ecohybrid_state(self):
        ecohybrid = self.lookup_enum('EcoHybrid')
        if ecohybrid == '-':
            return 'OFF'
        return ECOHYBRID(ecohybrid)
    
    @property
    def process_state(self):
        return DRYERPROCESSSTATE(self.lookup_enum('ProcessState'))
    
    @property
    def current_smartcourse(self):
        smartcourse = self.lookup_reference('SmartCourse')
        if smartcourse == '-':
            return 'OFF'
        else:
            return smartcourse

    @property
    def anticrease_state(self):
        return self.lookup_bit('Option1', 1)

    @property
    def childlock_state(self):
        return self.lookup_bit('Option1', 4)

    @property
    def selfcleaning_state(self):
        return self.lookup_bit('Option1', 5)

    @property
    def dampdrybeep_state(self):
        return self.lookup_bit('Option1', 6)

    @property
    def handiron_state(self):
        return self.lookup_bit('Option1', 7)



"""------------------for Washer"""

class WASHERSTATE(enum.Enum):
    
    OFF = "@WM_STATE_POWER_OFF_W"
    INITIAL = "@WM_STATE_INITIAL_W"
    PAUSE = "@WM_STATE_PAUSE_W"
    RESERVE = "@WM_STATE_RESERVE_W"
    DETECTING = "@WM_STATE_DETECTING_W"
    RUNNING = "@WM_STATE_RUNNING_W"
    RINSING = "@WM_STATE_RINSING_W"
    SPINNING = "@WM_STATE_SPINNING_W"
    SOAK = "@WM_STATE_SOAK_W"
    COMPLETE = "@WM_STATE_COMPLETE_W"
    FIRMWARE = "@WM_STATE_FIRMWARE_W"
    SMART_DIAGNOSIS = "@WM_STATE_SMART_DIAGNOSIS_W"


class WASHERSOIL(enum.Enum):

    LIGHT = "@WM_MX_OPTION_SOIL_LIGHT_W"
    LIGHT_NORMAL = "@WM_MX_OPTION_SOIL_LIGHT_NORMAL_W"
    NORMAL = "@WM_MX_OPTION_SOIL_NORMAL_W"
    NORMAL_HEAVY = "@WM_MX_OPTION_SOIL_NORMAL_HEAVY_W"
    HEAVY = "@WM_MX_OPTION_SOIL_HEAVY_W"
    
class WASHERWATERTEMP(enum.Enum):
 
    TAP_COLD = "@WM_MX_OPTION_TEMP_TAP_COLD_W"
    COLD = "@WM_MX_OPTION_TEMP_COLD_W"
    SEMI_WARM = "@WM_MX_OPTION_TEMP_SEMI_WARM_W"
    WARM = "@WM_MX_OPTION_TEMP_WARM_W"
    HOT = "@WM_MX_OPTION_TEMP_HOT_W"
    EXTRA_HOT = "@WM_MX_OPTION_TEMP_EXTRA_HOT_W"

class WASHERSPINSPEED(enum.Enum):
    
    NO_SELECT = "@WM_MX_OPTION_SPIN_NO_SPIN_W"
    LOW = "@WM_MX_OPTION_SPIN_LOW_W"
    MEDIUM = "@WM_MX_OPTION_SPIN_MEDIUM_W"
    HIGH = "@WM_MX_OPTION_SPIN_HIGH_W"
    EXTRA_HIGH = "@WM_MX_OPTION_SPIN_EXTRA_HIGH_W"

class WASHERRINSECOUNT(enum.Enum):
    
    NO_SELECT = "@CP_OFF_EN_W"
    ONE = "@WM_KR_TT27_WD_WIFI_OPTION_RINSECOUNT_1_W"
    TWO = "@WM_KR_TT27_WD_WIFI_OPTION_RINSECOUNT_2_W"
    THREE = "@WM_KR_TT27_WD_WIFI_OPTION_RINSECOUNT_3_W"
    FOUR = "@WM_KR_TT27_WD_WIFI_OPTION_RINSECOUNT_4_W"
    FIVE = "@WM_KR_TT27_WD_WIFI_OPTION_RINSECOUNT_5_W"

class WASHERDRYLEVEL(enum.Enum):
    
    NO_SELECT = "@WM_TERM_NO_SELECT_W"
    WIND = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_WIND_W"
    TURBO = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_TURBO_W"
    TIME_30 = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_TIME_30_W"
    TIME_60 = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_TIME_60_W"
    TIME_90 = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_TIME_90_W"
    TIME_120 = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_TIME_120_W"
    TIME_150 = "@WM_KR_TT27_WD_WIFI_OPTION_DRYLEVEL_TIME_150_W"

class WASHERERROR(enum.Enum):
    
    ERROR_dE2 = "@WM_KR_TT27_WD_WIFI_ERROR_DE2"
    ERROR_IE = "@WM_KR_TT27_WD_WIFI_ERROR_IE"
    ERROR_OE = "@WM_KR_TT27_WD_WIFI_ERROR_OE"
    ERROR_UE = "@WM_KR_TT27_WD_WIFI_ERROR_UE"
    ERROR_FE = "@WM_KR_TT27_WD_WIFI_ERROR_FE"
    ERROR_PE = "@WM_KR_TT27_WD_WIFI_ERROR_PE"
    ERROR_tE = "@WM_KR_TT27_WD_WIFI_ERROR_TE"
    ERROR_LE = "@WM_KR_TT27_WD_WIFI_ERROR_LE"
    ERROR_CE = "@WM_KR_TT27_WD_WIFI_ERROR_CE"
    ERROR_dHE = "@WM_KR_TT27_WD_WIFI_ERROR_DHE"
    ERROR_PF = "@WM_KR_TT27_WD_WIFI_ERROR_PF"
    ERROR_FF = "@WM_KR_TT27_WD_WIFI_ERROR_FF"
    ERROR_dCE = "@WM_KR_TT27_WD_WIFI_ERROR_DCE"
    ERROR_EE = "@WM_KR_TT27_WD_WIFI_ERROR_EE"
    ERROR_PS = "@WM_KR_TT27_WD_WIFI_ERROR_PS"
    ERROR_dE1 = "@WM_KR_TT27_WD_WIFI_ERROR_DE1"
    ERROR_LOE = "@WM_KR_TT27_WD_WIFI_ERROR_LOE"


class WasherDevice(Device):
    
    def monitor_start(self):
        """Start monitoring the device's status."""
        
        self.mon = Monitor(self.client.session, self.device.id)
        self.mon.start()
    
    def monitor_stop(self):
        """Stop monitoring the device's status."""
        
        self.mon.stop()
    
    def delete_permission(self):
        self._delete_permission()
    
    def poll(self):
        """Poll the device's current state.
        
        Monitoring must be started first with `monitor_start`. Return
        either an `ACStatus` object or `None` if the status is not yet
        available.
        """
        
        data = self.mon.poll()
        if data:
            res = self.model.decode_monitor(data)
            """
            with open('/config/wideq/washer_polled_data.json','w', encoding="utf-8") as dumpfile:
                json.dump(res, dumpfile, ensure_ascii=False, indent="\t")
            """
            return WasherStatus(self, res)
        
        else:
            return None

class WasherStatus(object):
    
    def __init__(self, washer, data):
        self.washer = washer
        self.data = data
    
    def lookup_enum(self, key):
        return self.washer.model.enum_name(key, self.data[key])
    
    def lookup_reference(self, key):
        return self.washer.model.reference_name(key, self.data[key])
    
    def lookup_bit(self, key, index):
        bit_value = int(self.data[key])
        bit_index = 2 ** index
        mode = bin(bit_value & bit_index)
        if mode == bin(0):
            return 'OFF'
        else:
            return 'ON'

    @property
    def is_on(self):
        run_state = WASHERSTATE(self.lookup_enum('State'))
        return run_state != WASHERSTATE.OFF
        
    @property
    def run_state(self):
        return WASHERSTATE(self.lookup_enum('State'))

    @property
    def pre_state(self):
        return WASHERSTATE(self.lookup_enum('PreState'))
    
    @property
    def remaintime_hour(self):
        return self.data['Remain_Time_H']
    
    @property
    def remaintime_min(self):
        return self.data['Remain_Time_M']
    
    @property
    def initialtime_hour(self):
        return self.data['Initial_Time_H']
    
    @property
    def initialtime_min(self):
        return self.data['Initial_Time_M']

    @property
    def reservetime_hour(self):
        return self.data['Reserve_Time_H']
    
    @property
    def reservetime_min(self):
        return self.data['Reserve_Time_M']

    @property
    def current_course(self):
        course = self.lookup_reference('Course')
        if course == '-':
            return 'OFF'
        else:
            return course

    @property
    def error_state(self):
        error = self.lookup_reference('Error')
        if error == '-':
            return 'OFF'
        elif error == 'No Error':
            return 'NO_ERROR'
        else:
            return WASHERERROR(error)

    @property
    def wash_option_state(self):
        soil = self.lookup_enum('Soil')
        if soil == '-':
            return 'OFF'
        return WASHERSOIL(soil)
    
    @property
    def spin_option_state(self):
        spinspeed = self.lookup_enum('SpinSpeed')
        if spinspeed == '-':
            return 'OFF'
        return WASHERSPINSPEED(spinspeed)

    @property
    def water_temp_option_state(self):
        water_temp = self.lookup_enum('WaterTemp')
        if water_temp == '-':
            return 'OFF'
        return WASHERWATERTEMP(water_temp)

    @property
    def rinsecount_option_state(self):
        rinsecount = self.lookup_enum('RinseCount')
        if rinsecount == '-':
            return 'OFF'
        return WASHERRINSECOUNT(rinsecount)

    @property
    def drylevel_option_state(self):
        drylevel = self.lookup_enum('DryLevel')
        if drylevel == '-':
            return 'OFF'
        return WASHERDRYLEVEL(drylevel)
   
    @property
    def current_smartcourse(self):
        smartcourse = self.lookup_reference('SmartCourse')
        if smartcourse == '-':
            return 'OFF'
        else:
            return smartcourse

    @property
    def freshcare_state(self):
        return self.lookup_bit('Option1', 1)

    @property
    def childlock_state(self):
        return self.lookup_bit('Option1', 3)

    @property
    def steam_state(self):
        return self.lookup_bit('Option1', 4)

    @property
    def turboshot_state(self):
        return self.lookup_bit('Option2', 7)

    @property
    def tubclean_count(self):
        return self.data['TCLCount']

    @property
    def load_level(self):
        return self.lookup_enum('LoadLevel')
