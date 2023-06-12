
require("./error_string")

const unirest = require("unirest");
const jwt = require('jsonwebtoken');
const axios = require('axios');
const Joi = require('joi');
const qs = require('qs');
const fs = require('fs');
const Redis = require('./cache');
const redis = new Redis().getInstance();
global.log4js = require("log4js");
//log4js.configure("./log4js.json");
//global.logger = log4js.getLogger();
//console = global.logger;


/**
 * call from -  ConfigureDevices,LinkApp,UnencryptedLink Functions <br>
 * Use - To configure Device scene mode to the external api <br>
 * possible status - 200,500
 *
 * @async
 * @param {object} sceneModeReqbody
 * @param {object} context
 * @param {string} authToken
 * @param {boolean} [bool=false]
 */
async function configureSceneMode(sceneModeReqbody, context, authToken, bool = false) {

  var responseStatus = {};
  var responseStatusBool = false;
  responseStatus.NodeID = sceneModeReqbody.NodeID;
  responseStatus.AppID = sceneModeReqbody.AppID;

  var sceneModeUrl = "https://" + process.env.CONTROLLER_URL + "/1.0/" + process.env.CONTROLLER_SERVICE_ID + "/management/ConfigureDeviceSceneMode";

  var sceneModeResp = await unirest.post(sceneModeUrl).headers({
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + authToken
  }).send(sceneModeReqbody)

  context.log("ConfigureDeviceSceneMode API called to Controller to URL " + sceneModeUrl + " with request body: " + sceneModeReqbody);
  delete sceneModeReqbody.AppID;
  try {
    if (sceneModeResp.code !== 200) {
      if (sceneModeResp === undefined) {
        context.log("SceneMode configuration failed.")
      } else {
        context.log("SceneMode configuration failed ResponseCode : " + sceneModeResp.code)
      }
      responseStatus.Code = 500;
      responseStatus.ConfigStatus = "Failed";
      responseStatus.ConfigType = "Scenemode";
      responseStatusBool = false;
    }
    else {

      responseStatus.Code = 200;
      responseStatus.ConfigStatus = "Success";
      responseStatus.ConfigType = "Scenemode";
      responseStatusBool = true;
    }

  } catch (error) {
    responseStatus.Code = 500;
    responseStatus.ConfigStatus = "Failed";
    responseStatus.ConfigType = "Scenemode";
    responseStatusBool = false;
  }

  return bool ? responseStatusBool : responseStatus;

}

/**
 * processGetImageURI
 *
 * @async
 * @param {array} arrayOfPromises
 * @param {null} [context=null]
 */
async function processGetImageURI(arrayOfPromises, context = null) {
  let responses = await Promise.all(arrayOfPromises);
  return responses;
}

/**
 * processNodeConfig
 *
 * @async
 * @param {array} arrayOfPromises
 * @param {null} [context=null]
 */
async function processNodeConfig(arrayOfPromises, context=null) {
  let responses = await Promise.all(arrayOfPromises);

  var res = {}
  res.ConfigType = "All";
  res.Status = true;
  res.DataPipelineConfigList = {};
  res.dataPipelineConfig = "NA";

  for (let response of responses) {
    if (response.Code === 500) {
      res.Status = false;
      break;
    }
    console.log(response)
    if (response.ConfigType === "Datapipeline" && response.Code === 201) {

      res.dataPipelineConfig = "Success";
      res.ConfigType = "All";
      res.Status = true;

      if (response.NodeID in res.DataPipelineConfigList) {
        if (!res.DataPipelineConfigList[response.NodeID].includes(response.AppID)) {
          res.DataPipelineConfigList[response.NodeID].push(response.AppID)
        }
      } else {
        res.DataPipelineConfigList[response.NodeID] = [response.AppID]
      }
      if (response.ConfigType === "Datapipeline" && res.dataPipelineConfig !== "Success" && response.Code !== 500) {

        if (response.Code === 201) {
          res.dataPipelineConfig = "Success";
          res.ConfigType = "All";
          res.Status = true;
        } else {
          res.dataPipelineConfig = "Fail";
          res.Status = false;
          res.ConfigType = "Datapipeline";
        }
      }
    }
  }

  return res;
}

/**
 * getImageURI
 *
 * @async
 * @param {object} node
 * @param {string} normalisationURI
 * @param {string} normalisationToken
 * @param {null} [context=null]
 */
async function getImageURI(node, normalisationURI, normalisationToken, context = null) {

  var startDate = new Date();
  startDate.setHours(startDate.getHours() - 24 * 7);
  var endDate = new Date();
  var imageURI = "";
  var accountServiceID = process.env.ACCOUNT_SERVICE_ID;

  try {
    ///GetSceneMarkManifest
    var sceneMarkurl = "https://" + normalisationURI + "/1.0/" + accountServiceID + "/getscenemarkmanifest";
    var sceneMarkBody = {
      "NodeIDs": [node.NodeID],
      "StartTime": startDate.toISOString(),
      "EndTime": endDate.toISOString(),
      "PageLength": 1,
      "ResetCache": true,
      "ReturnNICEItemTypes": true,
      "ReturnSceneMarkDates": true,
      "ReturnPage": true,
      "ListNICEItemTypes": [
        "Motion",
        "Face",
        "Human",
        "Vehicle",
        "Label",
        "TextLogoQRCode",
        "Animal",
        "Custom",
        "Scene",
        "Fire",
        "Furniture",
        "Bag",
        "Accessory",
        "Weapon",
        "Undefined"
      ],
      "ListEventTypes": [
        "Custom",
        "ItemPresence",
        "Loitering",
        "Intrusion",
        "Falldown",
        "Violence",
        "Fire",
        "Abandonment",
        "Express",
        "SpeedGate",
        "Xray",
        "Facility",
        "Scheduled"
      ],
      "ContinuationToken": null,
      "StartNumber": 0,
      "EndNumber": 0,
      "MaxNumber": 1
    }

    var sceneMarkResponse = await unirest.post(sceneMarkurl).headers({
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + normalisationToken
    }).strictSSL(false).send(sceneMarkBody)

    if (sceneMarkResponse.code === 200 && sceneMarkResponse.body.SceneMarkList !== null && sceneMarkResponse.body.SceneMarkList.length > 0) {

      imageURI = sceneMarkResponse.body.SceneMarkList[0].SceneDataThumbnail.SceneDataThumbnailURI;

    }
  } catch (e) {
    context.log('Error while Fetching thumbnail URI ' + e);
  }

  return { "NodeID": node.NodeID, "ImageURI": imageURI };

}

/**
 * call from - ConfigureDevices , UnLinkApp, SetTags, UnlinkDevice
 * Use - To Remove a piline from controller server's external api
 *
 * @async
 * @param {object} delPipelineConfigReqbody
 * @param {object} context
 * @param {string} authToken
 */
async function delDataPipeline(delPipelineConfigReqbody, context, authToken) {

  var responseStatus = {};

  var delPipelineConfigUrl = "https://" + process.env.CONTROLLER_URL + "/1.0/" + process.env.CONTROLLER_SERVICE_ID + "/management/DeleteDataPipelineConfig";

  var setPipelineConfigResp = await unirest.post(delPipelineConfigUrl).headers({
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + authToken
  }).send(delPipelineConfigReqbody)

  context.log("DeleteDataPipelineConfiguration API called to Controller for DeviceID " + delPipelineConfigReqbody.SourceID + " to URL " + delPipelineConfigUrl);
  context.log("DeleteDataPipelineConfig Request Body: " + delPipelineConfigReqbody);

  try {
    if (setPipelineConfigResp.code !== 200) {
      responseStatus.Code = 500;
      responseStatus.ConfigStatus = "Failed";
      responseStatus.ConfigType = "DelDatapipeline";

      context.log("Delete DataPipelineConfiguration API for Controller failed for DeviceID " + delPipelineConfigReqbody.SourceID + " to URL " + delPipelineConfigUrl);

    } else {
      context.log("DataPipeline configured successfully for DeviceID " + delPipelineConfigReqbody.SourceID);

      responseStatus.Code = setPipelineConfigResp.code;
      responseStatus.ConfigStatus = setPipelineConfigResp.body.Payload.Status;
      responseStatus.ConfigType = "DelDatapipeline";
    }
  } catch (error) {
    context.log("Unexpected Error in Delete DataPipelineConfiguration API for DeviceID " + delPipelineConfigReqbody.SourceID);
    responseStatus.Code = 500;
    responseStatus.ConfigStatus = "Failed";
    responseStatus.ConfigType = "DelDatapipeline";
  }


  return responseStatus;

}

/**
 * call from - ConfigureDevices , LinkApp, SetTags, SetTagsUnencrypted, UnencryptedLink App <br>
 * Use - To Configure a piline from controller server's external api
 *
 * @async
 * @param {object} setPipelineConfigReqbody
 * @param {object} context
 * @param {string} authToken
 */
async function configureDataPipeline(setPipelineConfigReqbody, context, authToken) {

  var responseStatus = "";
  var setPipelineConfigUrl = "https://" + process.env.CONTROLLER_URL + "/1.0/" + process.env.CONTROLLER_SERVICE_ID + "/management/SetDataPipelineConfig";

  var setPipelineConfigResp = await unirest.post(setPipelineConfigUrl).headers({
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + authToken
  }).send(setPipelineConfigReqbody)
  if (setPipelineConfigResp.code !== 201) {
    if (setPipelineConfigResp.code === undefined) {
      context.log("DataPipelineConfiguration failed for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID);
    } else {
      context.log("DataPipelineConfiguration failed for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID + ", failed with Response Code : " + setPipelineConfigResp.code);
    }
    responseStatus = 500
  } else {
    context.log("DataPipeline configured successfully for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID)
    responseStatus = 201
  }

  return responseStatus;

}

/**
 * call from - ConfigureDevices , LinkApp, SetTags, SetTagsUnencrypted, UnencryptedLink App<br>
 * Use - To Configure a piline from controller server's external api
 *
 * @async
 * @param {object} setPipelineConfigReqbody
 * @param {object} context
 * @param {string} authToken
 */
async function configureDataPipelineFull(setPipelineConfigReqbody, context, authToken) {

  var responseStatus = {};
  responseStatus.NodeID = setPipelineConfigReqbody.DeviceID;
  responseStatus.AppID = setPipelineConfigReqbody.AppID === process.env.ACCOUNT_SERVICE_ID ? setPipelineConfigReqbody.AppID : setPipelineConfigReqbody.AppInstanceID[0].substring(0, 28).padEnd(36, 0);

  var setPipelineConfigUrl = "https://" + process.env.CONTROLLER_URL + "/1.0/" + process.env.CONTROLLER_SERVICE_ID + "/management/SetDataPipelineConfig";

  var setPipelineConfigResp = await unirest.post(setPipelineConfigUrl).headers({
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + authToken
  }).send(setPipelineConfigReqbody)

  try {

    if (setPipelineConfigResp.code !== 201) {
      if (setPipelineConfigResp.code === undefined) {
        context.log("DataPipelineConfiguration failed for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID);
        responseStatus.Code = 500;
        responseStatus.ConfigStatus = "Failed";
        responseStatus.ConfigType = "Datapipeline";

      } else if (setPipelineConfigResp.code === 404) {
        responseStatus.Code = setPipelineConfigResp.code;
        responseStatus.ConfigStatus = setPipelineConfigResp.body.Payload.Status;
        responseStatus.ConfigType = "Datapipeline";

        context.log("DataPipelineConfiguration skipped for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID);
      } else {
        responseStatus.Code = setPipelineConfigResp.code;
        responseStatus.ConfigStatus = setPipelineConfigResp.body.Payload.Status;
        responseStatus.ConfigType = "Datapipeline";

        context.log("DataPipelineConfiguration failed for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID + ", failed with Response Code : " + setPipelineConfigResp.code);

      }

    } else {
      context.log("DataPipeline configured successfully for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID)

      responseStatus.Code = setPipelineConfigResp.code;
      responseStatus.ConfigStatus = setPipelineConfigResp.body.Payload.Status;
      responseStatus.ConfigType = "Datapipeline";

    }

  } catch (error) {
    context.log("DataPipelineConfiguration failed for DeviceID " + setPipelineConfigReqbody.DeviceID + " and AppId " + setPipelineConfigReqbody.AppID);
    responseStatus.Code = 500;
    responseStatus.ConfigStatus = "Failed";
    responseStatus.ConfigType = "Datapipeline";
  }


  return responseStatus;

}

/**
 * call from - Every function
 * Use - To check validation of request parameters
 *
 * @param {object} request_data_body
 * @param {array} params_array
 */
function setValidators(request_data_body, params_array) {
  if (request_data_body) {
    let obj = {};
    params_array.forEach(function (param) {
      obj[param.name] = Joi;
      if (param.type == "string") {
        obj[param.name] = obj[param.name].string()
      } else if (param.type == "number") {
        obj[param.name] = obj[param.name].number()
      } else if (param.type == "boolean") {
        obj[param.name] = obj[param.name].boolean()
      } else if (param.type == "array") {
        obj[param.name] = obj[param.name].array()
      } else if (param.type == "object") {
        obj[param.name] = obj[param.name].object()
      }

      if (param.pattern) {
        obj[param.name] = obj[param.name].pattern(new RegExp(param.pattern))
      }
      if (param.required) {
        obj[param.name] = obj[param.name].required();
      }
      if (param.min != undefined) {
        obj[param.name] = obj[param.name].min(Number(param.min))
      }
      if (param.max != undefined) {
        obj[param.name] = obj[param.name].min(Number(param.max))
      }
      if (param.ref != undefined) {
        obj[param.name] = obj[param.name].ref(param.ref)
      }
      if (param.email) {
        obj[param.name] = obj[param.name].email()
      }
    })
    
    const schema = Joi.object(obj);
    const validation = schema.validate(request_data_body, { abortEarly: false });
    if (validation.error) {
      return ({ success: false, error_code: ERROR_CODE.ERROR_CODE_PARAMETER_MISSING_OR_INVALID, error_message: ERROR_MESSAGE.ERROR_CODE_PARAMETER_MISSING_OR_INVALID, validations: validation.error });
    } else {
      return ({ success: true });
    }
  }
}

/**
 * call from - Every function <br>
 * Use - To check validation of request parameters <br>
 *
 * @async
 * @param {object} request_data_body
 * @param {array} params_array
 * @param {object} inner_params
 * @param {object} request_headers
 * @param {array} headers_array
 */
async function check_request_params(request_data_body, params_array, inner_params, request_headers, headers_array) {
  // context.log("==========check_request_params========")
  // context.log(headers_array)
  let response = { success: true };
  if (params_array && params_array.length){
    response = await setValidators(request_data_body, params_array)
    if (!response.success){
      return (response);
    }
  }
  /*if (headers_array && headers_array.length) {
    response = await setValidators(request_headers, headers_array)
    if (!response.success) {
      return (response);
    }
  }*/
  return (response);
}

/**
 * encryptPassword
 *
 * @param {string} password
 */
function encryptPassword (password) {
  var crypto = require('crypto');
  try {
    return crypto.createHash('md5').update(password).digest('hex');
  } catch (error) {
    // console.error(error);
  }
};

/**
 * call from - ConfigureNotification, GetAccountNode, GetAppControlObject, GetControlObject, GetTags, GetNotifications, SetTags<br>
 * Use - To validate device token from the authorize header<br>
 *
 * @async
 * @param {object} headers
 * @param {boolean} [check=false]
 */
async function deviceTokenValidate(headers, check = false) {
  var cert = process.env.PEM_CERT;
  cert = Buffer.from(cert, "utf-8");
  if (check === false) {
    return ({ success: true });
  }else{
    try {
      let decoded = jwt.verify(headers['authorization'], cert);
      if (decoded){
        return ({ success: true });
      }else{
        return ({ success: false });
      }
    } catch (error) {
      console.log(headers);
      console.log(error);
      return ({ success: false });
    }
  }

  /*var bearerHeader = headers['authorization'];
  var accountServiceID = process.env.ACCOUNT_SERVICE_ID;

  if (bearerHeader !== null && bearerHeader !== '' && bearerHeader !== undefined) {

    var bearer = bearerHeader.split(' ');
    var bearerToken = bearer[1];

    if (bearerToken) {
      var decoded = {};
      var verification = false;

      try {
        var validateJWTtUrl = process.env.KEYSERVICE_URL + "/api/ValidateJWT?code=7HznBE6dhSlP3zaZZpcWosaLpRMfjWuY9YKaOwb6SHsyeHxa0UdbaQ==";
        var validateJWTPayload = {
          "SignedObject": bearerToken
        };

        var validateJWTResponse = await unirest.post(validateJWTtUrl).headers({
          "Accept": "application/json",
          "Content-Type": "application/json"
        }).send(validateJWTPayload);

        if (validateJWTResponse.code === 200) {
          decoded = JSON.parse(validateJWTResponse.body.decryptedObject);
          verification = validateJWTResponse.body.passedVerification;
        }
        else {
          return ({ success: false });
        }
      }
      catch (e) {
        return ({ success: false });
      }


      var exp = decoded.exp;
      var nbf = decoded.nbf;
      var aud = decoded.aud;
      var curDate = Date.now() / 1000;

      if (curDate > exp || curDate < nbf || accountServiceID !== aud || verification !== true) {
        return ({ success: false });
      }

      return ({ success: true });
    }
  }

  return ({ success: false });*/
};

/**
  * ValidateAADTokenValidate
  *
  * @async
  * @param {object} headers
  */
 async function ValidateAADTokenValidate(headers) {

  return ({ success: true });
};

/**
  * call from - ConfigureNotification, GetAccessToken, GetNotifications, GetTags, SetNotifications, SetTags<br>
  * Use - Will decrypt object with cmf and return that to response with the Keyservice external api<br>
  *
  * @async
  * @param {object} body
  * @param {object} context
  * @param {boolean} [check=false]
  */
 async function decryptCMF(body, context, check = false) {

  if (check === false) {
    body.Payload = JSON.stringify(body.Payload);
    return ({
      "DecryptedPayload": body,
      "EncryptionKey": "Test",
      "Success": true
    });
  }

  var encryptionKey = body.EncryptionKey;
  var encryptedPayload = body.EncryptedAndSignedObject;
  var decryptedPayload = '';
  var status = false;

  if (encryptionKey !== null && encryptionKey !== '' && encryptionKey !== undefined
    && encryptedPayload !== null && encryptedPayload !== '' && encryptedPayload !== undefined) {
    try {

      var decryptUrl = process.env.KEYSERVICE_URL + "/api/DecryptAndValidateCMF?code=z2N3haHEpz66Uc7kNdTT0r3bESPpotn6rClB9VULJIAELwAtslA1XQ==";

      var decryptPayload = {
        "EncryptedAndSignedObject": encryptedPayload
      }

      var decryptResponse = await unirest.post(decryptUrl).headers({
        "Accept": "application/json",
        "Content-Type": "application/json"
      }).send(decryptPayload)

      if (decryptResponse.code === 200) {
        decryptedPayload = decryptResponse.body.decryptedObject;
        status = true;
      }

    }
    catch (e) {
      context.log("Error while decrypting Request CMF Payload" + e);
    }

  }

  return ({
    "DecryptedPayload": decryptedPayload,
    "EncryptionKey": encryptionKey,
    "Success": status
  });

};

/**
 * call from -  GetAppcontrolObject,Get Control Object, GetDateTime, GetPrivacyObject, UnencryptedGetAppControl<br>
 * Use - Will decrypt device object with cmf and return that to response with the Keyservice external api<br>
 *
 * @async
 * @param {object} body
 * @param {object} context
 * @param {boolean} [check=false]
 */
async function decryptDeviceCMF(body, context, check = false) {

  var encryptedPayload = {};
  var decryptUrl = '';
  var decryptedPayload = '';
  var status = false;
  var cmfHeader = '';
  var algorithm = '';
  var keyAlgorithm = '';
  var reqType = '';

  if (check === false) {
    body.Payload = JSON.stringify(body.Payload);
    return ({
      "ReqPayload": body.Payload,
      "EncryptionKey": 'Test',
      "CMFHeader": body,
      "Success": true,
      "Algorithm": 'Test',
      "KeyAlgorithm": 'Test'
    });
  }

  if(body.EncryptedPayload){
    encryptedPayload = body.EncryptedPayload;
    decryptUrl = process.env.KEYSERVICE_URL + "/api/DecryptAndValidateCMF?code=z2N3haHEpz66Uc7kNdTT0r3bESPpotn6rClB9VULJIAELwAtslA1XQ==";
    reqType = 'v1';
  }else{
    encryptedPayload = body.SignedCMF;
    decryptUrl = process.env.KEYSERVICE_URL + "/api/DecryptAndValidateCMFV2?code=5CwcjGoEb5__MbXAKscfZcnkFmbdaGP-r9Mg6qfYvf2kAzFukhkWcg==";
    reqType = 'v2';
  }


  var requestPayload = JSON.parse(Buffer.from(encryptedPayload.split('.')[0], 'base64').toString('ascii'));
  var encryptionKey = requestPayload.x5c[0];
  var alg = requestPayload.alg;

  if (encryptionKey !== null && encryptionKey !== '' && encryptionKey !== undefined
    && encryptedPayload !== null && encryptedPayload !== '' && encryptedPayload !== undefined) {
    try {

      var decryptPayload = {
        "EncryptedAndSignedObject": encryptedPayload
      }

      var decryptResponse = await unirest.post(decryptUrl).headers({
        "Accept": "application/json",
        "Content-Type": "application/json"
      }).send(decryptPayload)

      if (decryptResponse.code === 200 && decryptResponse.body.passedVerification) {
        if(reqType == 'v1'){
          decryptedPayload = decryptResponse.body.deviceDecryptedObject;
          cmfHeader = JSON.parse(decryptedPayload.CMFHeader);
          reqPayload = decryptedPayload["AccessToken&Payload"].PayloadObject;  
        }else{
          decryptedPayload = decryptResponse.body.decryptedObject;
          cmfHeader = decryptedPayload;
          cmfHeader.CommandID = 1;
          reqPayload = JSON.parse(decryptedPayload["Payload"]);
          reqPayload.DeviceID = cmfHeader.SourceEndPointID;
        }
        status = true;
        if (alg.substr(0, 2) === "RS") {
          algorithm = "RSA-OAEP-256";
          keyAlgorithm = "RSA";
        } else if (alg.substr(0, 2) === "ES") {
          algorithm = "ECDH-ES+A256KW";
          keyAlgorithm = "ES256";
        }
      }

    }
    catch (e) {
      context.log("Error while calling DecryptAndValidateCMF API to the key service. url: " + decryptUrl + " Failed payload " + decryptPayload + e);
    }

  }
  if (reqType == "v1") {
    context.log("DecryptAndValidateCMF API success! URL: " + process.env.KEYSERVICE_URL + "/api/DecryptAndValidateCMF " + " Payload: " + encryptedPayload);
  } else if (reqType == "v2"){
    context.log("DecryptAndValidateCMF API success! URL: " + process.env.KEYSERVICE_URL + "/api/DecryptAndValidateCMFV2 "+ " Payload: " + encryptedPayload);
  }
  context.log("DecryptedPayload: " + reqPayload);

  return ({
    "DecryptedPayload": decryptedPayload,
    "EncryptionKey": encryptionKey,
    "CMFHeader": cmfHeader,
    "Success": status,
    "ReqPayload": reqPayload,
    "Algorithm": algorithm,
    "KeyAlgorithm": keyAlgorithm
  });

};

/**
 * call from -  ConfigureNotifications,GetAccessToken,GetAppControlObject,GetControlObject,GetDateTime,GetNotifications,GetTags,SetNotifications,SetTags,UnencryptedGetAppControl<br>
 * Use - Will encrypt reponse object with cmf and return that to response with the Keyservice external api<br>
 *
 * @async
 * @param {object} payload
 * @param {string} encryptionKey
 * @param {object} context
 * @param {string} algorithm
 * @param {string} keyAlgorithm
 * @param {boolean} [check=false]
 */
async function encryptCMF(payload, encryptionKey, context, algorithm, keyAlgorithm, check = false) {

  if (check === false) {
    return ({
      "EncryptedPaylod": {
        "body": payload
      },
      "Success": true
    });
  }

  var signingKeyID = process.env.ACCOUNT_SERVICE_ID;
  var encryptedPayload = '';
  var status = false;
  try {
    var encryptUrl = process.env.KEYSERVICE_URL + "/api/EncryptAndSignCMF?code=JxnmEUh2MsPUl3QE7JETfmR22hO0ZFPtlbTzI1LqvZxhjFxm8Ygy1A==";

    var encryptPayload = {
      "Algorithm": algorithm,
      "KeyAlgorithm": keyAlgorithm,
      "EncryptionKey": encryptionKey,
      "SigningKeyID": signingKeyID,
      "ObjectInClearText": payload
    }


    var encryptResponse = await unirest.post(encryptUrl).headers({
      "Accept": "application/json",
      "Content-Type": "application/json"
    }).send(JSON.stringify(encryptPayload));

    if (encryptResponse.code === 200) {
      encryptedPayload = encryptResponse;
      status = true;
    }
  }
  catch (e) {
    context.log("Error while encrypting AppControlObject Response Payload " + e);
  }


  return ({
    "EncryptedPaylod": encryptedPayload,
    "Success": status
  });
};

/**
 * call from -  Get Privacy Object <br>
 * Use - Will encrypt privacy object with cmf and return that to response with the Keyservice external api <br>
 *
 * @async
 * @param {object} payload
 * @param {string} encryptionKey
 * @param {object} context
 * @param {string} algorithm
 * @param {string} keyAlgorithm
 * @param {boolean} [check=false]
 * @param {string} encryptedSceneEncryptionKey
 * @returns {unknown}
 */
async function encryptPrivacyCMF(payload, encryptionKey, context, algorithm, keyAlgorithm, check = false, encryptedSceneEncryptionKey) {

  if (check === false) {
    return ({
      "EncryptedPaylod": {
        "body": payload
      },
      "Success": true
    });
  }

  var signingKeyID = process.env.ACCOUNT_SERVICE_ID;
  var encryptedPayload = '';
  var status = false;
  try {
    var encryptUrl = process.env.KEYSERVICE_URL + "/api/CreatePrivacyObject2?code=pu6Mu4K6UPbWNUOM/2n1hOd/hgCbikEu51/sPW8MsJlC0xoLF6fuaQ==";

    var encryptPayload = {
      "Algorithm": algorithm,
      "KeyAlgorithm": keyAlgorithm,
      "EncryptionKey": encryptionKey,
      "SigningKeyID": signingKeyID,
      "ObjectInClearText": payload,
      "EncryptedSceneEncryptionKey": encryptedSceneEncryptionKey
    }


    var encryptResponse = await unirest.post(encryptUrl).headers({
      "Accept": "application/json",
      "Content-Type": "application/json"
    }).send(JSON.stringify(encryptPayload));

    if (encryptResponse.code === 200) {
      encryptedPayload = encryptResponse;
      status = true;
    }
  }
  catch (e) {
    context.log("Error while encrypting Privacy Response Payload " + e);
  }


  return ({
    "EncryptedPaylod": encryptedPayload,
    "Success": status
  });
};

/**
 * call from -  Configure Devices,Configure Notification, Link App, Link Device, Set Notification, Set Tags, Set Tags Unencrypted, Unencrypted LinkApp, Unlink App, Unlink Device <br>
 * Use - Will generate access token from the client id and token and return access token and also store that token in redis to reuse it again <br>
 *
 * @async
 * @param {object} context
 */
async function generateControllerAADToken(context) {

  var controllerToken = "";
  try {
    controllerToken = await redis.get('AAD_CONTROLLER_TOKEN') || '';
  } catch (e) {
    context.log('Error while fetching token from cache' + e);
  }

  if (controllerToken == '' || controllerToken == null) {
    try {
      var authorityHostUrl = process.env.AUTHORITY;
      var niceasApplicationId = process.env.NICEAS_CLIENT_ID; // Application Id of app registered under AAD.
      var niceasClientSecret = process.env.NIEAS_CLIENT_SECRET; // Secret generated for app. Read this environment variable.
      var controllerResource = process.env.CONTROLLER_RESOURCE_ID; // URI that identifies the resource for which the token is valid.


      var controllerTokenResponse = await axios.post(authorityHostUrl, qs.stringify({ grant_type: 'client_credentials', client_id: niceasApplicationId, client_secret: niceasClientSecret, resource: controllerResource }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
      controllerToken = controllerTokenResponse.data.access_token;
      redis.set('AAD_CONTROLLER_TOKEN', controllerToken, 'EX', 60 * 60 * 23).catch(error => {
        context.log('Error while setting AAD token in cache ' + error);
      });
    }
    catch (e) {
      context.log('Error while generating token ' + e);
    }
  }

  return controllerToken;
}

/**
 * call from -  Every api which are sending responses
 * Use - Sending common response format and put log for every response
 * possible status - 500,400,401,403,404,409,503
 *
 * @async
 * @param {object} context
 * @param {string} status
 * @param {object} body
 * @param {string} responseCode
 * @param {string} responseMessage
 */
async function sendCommonResponse(context, status, body, responseCode, responseMessage, headers = {'Content-Type': 'application/json'}) {
  if (status == 400 || status == 401 || status == 403 || status == 404 || status == 409 || status == 500 || status == 503){
    context.log("=======" + status + "=======");
    context.log("=======Request=======");
    context.log(context.req);
    context.log("=======Response=======");
    context.log(body);
  }
  return context.res = {
    status: status,
    body: body,
    headers: headers
  };
}


module.exports = {
  check_request_params,
  encryptPassword,
  deviceTokenValidate,
  configureSceneMode,
  configureDataPipelineFull,
  configureDataPipeline,
  delDataPipeline,
  processGetImageURI,
  processNodeConfig,
  generateControllerAADToken,
  ValidateAADTokenValidate,
  encryptPrivacyCMF,
  decryptDeviceCMF,
  getImageURI,
  decryptCMF,
  encryptCMF,
  sendCommonResponse,
  //publicIp,
  unirest,
  axios,
  qs
}
