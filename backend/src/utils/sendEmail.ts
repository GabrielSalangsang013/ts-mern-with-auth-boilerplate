import nodemailer, { TransportOptions } from "nodemailer";

type SendEmailOptions = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

const sendEmail = async ({ to, subject, text, html }: SendEmailOptions) => {
  const transporter = nodemailer.createTransport({
    // * Cast the options to the TransportOptions type
    host: process.env["SMTP_HOST"] as string,
    port: process.env["SMTP_PORT"] as string,
    secure: process.env["NODE_ENV"] as string === "PRODUCTION" ? true : false as boolean,
    auth: {
      user: process.env["SMTP_USER"] as string,
      pass: process.env["SMTP_PASSWORD"] as string,
    }
  } as TransportOptions); // * Cast the object to TransportOptions

  const emailOptions = {
    from: `MERN <${process.env["EMAIL_FROM"] as string}>`,
    to,
    subject,
    text,
    html,
  };

  // * Sending email activation account
  transporter.sendMail(emailOptions, (error: any, info: any) => {
    if (error) {
      console.log({
        fileName: 'sendEmail.ts',
        errorDescription: 'There is something problem on the sending the activation link to the user via email.',
        errorLocation: 'sendEmail',
        error: error
      });
    }
  });
};

export default sendEmail;
