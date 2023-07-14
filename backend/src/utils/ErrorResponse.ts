class ErrorResponse extends Error {
  statusCode: number;
  errorCode: number;

  constructor(statusCode: number, message: string, errorCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

export default ErrorResponse;