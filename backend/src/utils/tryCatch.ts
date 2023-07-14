import express from 'express';

const tryCatch = (controller: any) => async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      await controller(req, res);
    } catch (error) {
      return next(error);
    }
};

export default tryCatch;