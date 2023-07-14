// * -------------------- REGISTER ACCOUNT ACTIVATION EMAIL TEMPLATE --------------------
export const ACCOUNT_ACTIVATION_EMAIL_SUBJECT: string = "MERN with Auth - Account Activation";
export const ACCOUNT_ACTIVATION_EMAIL_TEXT: string = "Your account will be activated by clicking the link below";
export const ACCOUNT_ACTIVATION_EMAIL_HTML = (username: string, activateAccountURL: string): string => {
    return `
        <div style="background-color: #f1f1f1; padding-bottom: 130px; height: 600px; width: 100%;">
            <div style="background-color: rgb(29, 30, 43); height: 225px; width: 100%;">
                <div style="padding-top: 100px;">
                    <div style="background-color: white; width: 500px; margin: auto; border-radius: 3px; padding: 35px 40px; box-sizing: border-box;">
                        <div style="">
                            <div style="width: 100%;">
                                <h1 style="color: black; text-align:center; margin: 0px; margin-bottom: 35px; font-family: 'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; font-weight: 400; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; font-size: 2rem;">Welcome ${username}!</h1>
                            </div>
                            <div style="width: 100%;">
                                <img style="pointer-events: none; display: block; margin-left: auto; margin-right: auto; width: 70px; margin: auto;" src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/a7/React-icon.svg/2300px-React-icon.svg.png" alt="React icon">
                            </div>
                            <span style="margin-top: 50px; display: block; margin-left: 125px;">
                                <a style="text-decoration: none;" href=${activateAccountURL}>
                                    <span style="width: 130px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; cursor:pointer; margin-top: 40px; padding: 20px; border: 0px; background-color: #54bbfb; color: white; font-size: 1rem; border-radius: 3px; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility;" type="button">Activate Account</span>
                                </a>
                            </span>
                            <div style="margin-top: 50px;">
                                <p style="font-size: 1rem; color: black; text-align: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-weight: lighter; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility;">Thank you for registering with us. To activate your account, please click the button above.</p>
                            </div>
                            <div style="width: 100%; padding: 2px 40px; box-sizing: border-box;">
                                <div style="display: table; margin: auto; margin-top: 40px; margin-bottom: 20px;">
                                    <a style="border-radius: 50px; text-decoration: none;" href="#">
                                        <img style="width: 20px; height: 20px;" src="https://cdn-icons-png.flaticon.com/512/174/174857.png" alt="Linkedin icon">
                                    </a>
                                    <a style="border-radius: 50px; text-decoration: none; margin: 0px 20px;" href="#">
                                        <img style="width: 20px; height: 20px;" src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/6f/Logo_of_Twitter.svg/512px-Logo_of_Twitter.svg.png?20220821125553" alt="Twitter icon">
                                    </a>
                                    <a style="border-radius: 50px; text-decoration: none;" href="#">
                                        <img style="width: 20px; height: 20px;" src="https://cdn-icons-png.flaticon.com/512/5968/5968764.png" alt="Linkedin icon">
                                    </a>
                                </div>
                                <p style="text-align: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: rgb(131, 131, 131); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; font-size: 0.875rem;">Please note that you received this email because you signed up to our website.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// * ------------- RECOVER ACCOUNT RESET PASSWORD EMAIL TEMPLATE -------------
export const RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT: string = "MERN with Auth - Recovery Account Reset Password";
export const RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT: string = "You can update your password to recover your account by clicking the link below";
export const RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML = (username: string, recoverAccountResetPasswordURL: string): string => {
    return `
        <div style="background-color: #f1f1f1; padding-bottom: 130px; height: 600px; width: 100%;">
            <div style="background-color: rgb(29, 30, 43); height: 225px; width: 100%;">
                <div style="padding-top: 100px;">
                    <div style="background-color: white; width: 500px; margin: auto; border-radius: 3px; padding: 35px 40px; box-sizing: border-box;">
                        <div style="">
                            <div style="width: 100%;">
                                <img style="pointer-events: none; display: block; margin-left: auto; margin-right: auto; width: 50px; margin: auto; margin-bottom: 20px;" src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/a7/React-icon.svg/2300px-React-icon.svg.png" alt="React icon">
                            </div>
                            <div style="width: 100%;">
                                <h1 style="color: black; text-align:center; margin: 0px; margin-bottom: 25px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-weight: 500; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; font-size: 1.2rem;">Recover Account - Reset Password</h1>
                            </div>

                            <div style="margin-top: 0px;">
                                <p style="font-size: 1rem; color: black; text-align: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-weight: 400; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility;">
                                    Hi <strong>${username}!</strong> To reset your password or if you have lost it, simply click the button below to initiate the process.
                                </p>
                            </div>

                            <span style="margin-top: 50px; display: block; margin-left: 125px;">
                                <a style="text-decoration: none;" href=${recoverAccountResetPasswordURL}>
                                    <span style="width: 130px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; cursor:pointer; margin-top: 40px; padding: 20px; border: 0px; background-color: #54bbfb; color: white; font-size: 1rem; border-radius: 3px; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility;" type="button">Reset Your Password</span>
                                </a>
                            </span>
                            
                            <div style="width: 100%; padding: 2px 0px; box-sizing: border-box; margin-top: 30px;">
                                <p style="text-align: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: rgb(131, 131, 131); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; font-size: 0.875rem;">
                                    If you did not request an account recovery or password reset, you can safely disregard this email. Remember, only someone with access to your email can initiate a password reset for your account. <br/><br/>React Team
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// * ------------- MULTI FACTOR AUTHENTICATION LOGIN ACCOUNT EMAIL TEMPLATE -------------
export const MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_SUBJECT: string = "MERN with Auth - Multi Factor Authentication Verification Login Code ";
export const MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_TEXT: string = "Here's the code for your authentication.";
export const MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_HTML = (username: string, sendVerificationCodeLogin: string): string => {
    return `
        <div style="background-color: #f1f1f1; padding-bottom: 130px; height: 600px; width: 100%;">
            <div style="background-color: rgb(29, 30, 43); height: 225px; width: 100%;">
                <div style="padding-top: 100px;">
                    <div style="background-color: white; width: 500px; margin: auto; border-radius: 3px; padding: 35px 40px; box-sizing: border-box;">
                        <div style="">
                            <div style="width: 100%;">
                                <img style="pointer-events: none; display: block; margin-left: auto; margin-right: auto; width: 50px; margin: auto; margin-bottom: 20px;" src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/a7/React-icon.svg/2300px-React-icon.svg.png" alt="React icon">
                            </div>
                            <div style="width: 100%;">
                                <h1 style="color: black; text-align:center; margin: 0px; margin-bottom: 25px; font-family: 'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; font-weight: 500; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; font-size: 1.2rem;">Hello ${username}!</h1>
                            </div>

                            <div style="margin-top: 0px;">
                                <p style="font-size: 1rem; color: black;  text-align: center; font-family: 'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; font-weight: 300; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility;">
                                    Please utilize the provided verification code on the website to complete the verification process.
                                </p>
                            </div>

                            <div style="margin-top: 20px;">
                                <h1 style="display: block; text-align: center; font-family: arial; font-weight: bold;">${sendVerificationCodeLogin}</h1>
                            </div>
                            
                            <div style="width: 100%; padding: 2px 40px; box-sizing: border-box;">
                                <div style="display: table; margin: auto; margin-top: 40px; margin-bottom: 20px;">
                                    <a style="border-radius: 50px; text-decoration: none;" href="#">
                                        <img style="width: 20px; height: 20px;" src="https://cdn-icons-png.flaticon.com/512/174/174857.png" alt="Linkedin icon">
                                    </a>
                                    <a style="border-radius: 50px; text-decoration: none; margin: 0px 20px;" href="#">
                                        <img style="width: 20px; height: 20px;" src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/6f/Logo_of_Twitter.svg/512px-Logo_of_Twitter.svg.png?20220821125553" alt="Twitter icon">
                                    </a>
                                    <a style="border-radius: 50px; text-decoration: none;" href="#">
                                        <img style="width: 20px; height: 20px;" src="https://cdn-icons-png.flaticon.com/512/5968/5968764.png" alt="Linkedin icon">
                                    </a>
                                </div>
                                <p style="text-align: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: rgb(131, 131, 131); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; font-size: 0.875rem;">
                                    If you did not initiate this request, you may disregard this email. Thank you! <br/><br/>React Team
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}