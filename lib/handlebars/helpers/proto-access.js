/* eslint-disable dot-notation, no-proto */
import { createNewLookupObject } from './create-new-lookup-object';

export function createProtoAccessControl(runtimeOptions) {
  let defaultMethodWhiteList = Object.create(null);
  defaultMethodWhiteList['constructor'] = false;
  defaultMethodWhiteList['__defineGetter__'] = false;
  defaultMethodWhiteList['__defineSetter__'] = false;
  defaultMethodWhiteList['__lookupGetter__'] = false;

  let defaultPropertyWhiteList = Object.create(null);
  defaultPropertyWhiteList['__proto__'] = false;

  return {
    properties: {
      whitelist: createNewLookupObject(
        defaultPropertyWhiteList,
        runtimeOptions.allowedProtoProperties
      ),
      defaultValue: runtimeOptions.allowProtoPropertiesByDefault
    },
    methods: {
      whitelist: createNewLookupObject(
        defaultMethodWhiteList,
        runtimeOptions.allowedProtoMethods
      ),
      defaultValue: runtimeOptions.allowProtoMethodsByDefault
    }
  };
}

export function resultIsAllowed(result, protoAccessControl, propertyName) {
  if (typeof result === 'function') {
    return checkWhiteList(protoAccessControl.methods, propertyName);
  } else {
    return checkWhiteList(protoAccessControl.properties, propertyName);
  }
}

function checkWhiteList(protoAccessControlForType, propertyName) {
  if (protoAccessControlForType.whitelist[propertyName] !== undefined) {
    return protoAccessControlForType.whitelist[propertyName] === true;
  }
  if (protoAccessControlForType.defaultValue !== undefined) {
    return protoAccessControlForType.defaultValue;
  }
  return false;
}
