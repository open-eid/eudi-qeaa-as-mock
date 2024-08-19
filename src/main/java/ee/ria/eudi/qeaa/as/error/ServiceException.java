package ee.ria.eudi.qeaa.as.error;

import lombok.Getter;

@Getter
public class ServiceException extends RuntimeException {
    private final ErrorCode errorCode;

    public ServiceException(String message) {
        this(ErrorCode.INVALID_REQUEST, message);
    }

    public ServiceException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = ErrorCode.INVALID_REQUEST;
    }

    public ServiceException(Throwable cause) {
        super(cause);
        this.errorCode = ErrorCode.SERVICE_EXCEPTION;
    }

    public ServiceException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
