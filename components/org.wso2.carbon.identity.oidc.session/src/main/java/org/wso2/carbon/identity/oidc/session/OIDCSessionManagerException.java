package org.wso2.carbon.identity.oidc.session;


import org.wso2.carbon.identity.base.IdentityException;

public class OIDCSessionManagerException extends IdentityException{
    public OIDCSessionManagerException(String message) {
        super(message);
    }

    public OIDCSessionManagerException(String errorCode, String message) {
        super(errorCode, message);
    }

    public OIDCSessionManagerException(String message, Throwable cause) {
        super(message, cause);
    }

    public OIDCSessionManagerException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
