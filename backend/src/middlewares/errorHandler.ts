import express from 'express';
import ErrorResponse from "../utils/ErrorResponse.js"; // * UTILITY
import * as errorCodes from '../constants/v1AuthenticationErrorCodes.js'; // * CONSTANTS
import { Error } from '../types/index.js';

function errorHandler (error: Error, req: express.Request, res: express.Response, next: express.NextFunction) {
    // * THIS IS ERROR FROM THE MONGOOSE MODEL VALIDATION USER INPUT
    if (error.name === "ValidationError") {
        const message: any = Object.values(error.errors).map((val: any) => val.message);
        error = new ErrorResponse(400, message, errorCodes.MONGOOSE_VALIDATION_ERROR);
    }

    if (process.env["NODE_ENV"] as string === "PRODUCTION") {
        return res.status(500).json({
            message: "There is something problem on the server. Please try again later.",
            errorCode: errorCodes.SERVER_ERROR
        });
    }

    return res.status(error.statusCode || 500).json({
        message: error.message || "There is something problem on the server. Please try again later.",
        errorCode: error.errorCode || errorCodes.SERVER_ERROR
    });
}

export default errorHandler;