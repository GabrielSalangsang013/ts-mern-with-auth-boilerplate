import { useState, useEffect } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { Formik, Form, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './LoginVerificationCode.module.css';
import logo from '../../../assets/logo-header.png';

import { useSelector, useDispatch } from 'react-redux';
import { setDisable, setNotDisable, hasError, hasNoError } from '../../../actions';
import { AllReducers } from '../../../interfaces';

import CustomButton from '../../../components/AllRoutes/CustomButton/CustomButton';
import CustomAlert from '../../../components/AllRoutes/CustomAlert/CustomAlert';
import CustomInput from '../../../components/AllRoutes/CustomInput/CustomInput';
import Layout from '../../../components/AllRoutes/Layout/Layout';

type valuesSubmitType = {
    verificationCodeLogin: string
}

type valuesGoogleSubmitType = {
    googleAuthenticatorCodeLogin: string
}

const LoginVerificationCode = () => {
    const navigate = useNavigate();
    const [showButtonDisplayGoogleAuthenticatorForm, setShowButtonDisplayGoogleAuthenticatorForm] = useState(false);
    const [useGoogleAuthenticatorForm, setUseGoogleAuthenticatorForm] = useState(false);
    const [authenticatedUser]:any = useOutletContext();
    const error = useSelector((state: AllReducers) => state.error);
    const dispatch = useDispatch();

    const initialValues = {
        verificationCodeLogin: ''
    };

    const initialValuesGoogleAuthenticator = {
        googleAuthenticatorCodeLogin: ''
    };

    const validationSchema = Yup.object().shape({
        verificationCodeLogin: Yup.string()
            .required('Verification login code is required')
            .min(7, 'Verification login code must be 7 characters')
            .max(7, 'Verification login code must be 7 characters')
            .matches(/^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]{7}$/, 'Verification login code must be 7 characters and contain only numbers and letters')
            .test(
                'verificationCodeLogin', 
                'Verification login code should not contain sensitive information', 
                value => {
                    return !/\b(admin|root|superuser)\b/i.test(value);
                }
            )
            .test(
                'verificationCodeLogin', 
                'Invalid verification login code format or potentially unsafe characters', 
                value => {
                    const sanitizedValue = escape(value);
                    return sanitizedValue === value;
                }
            )
    });

    const validationSchemaGoogleAuthenticator = Yup.object().shape({
        googleAuthenticatorCodeLogin: Yup.string()
            .required('Google Authenticator Code Login is required')
            .matches(/^\d{6}$/, 'Code must be a 6-digit number'),
    });

    const handleSubmit = (values: valuesSubmitType) => {
        const {verificationCodeLogin} = values;
        const sanitizedVerificationCodeLogin = DOMPurify.sanitize(verificationCodeLogin);
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/verification-code-login`, {
            verificationCodeLogin: sanitizedVerificationCodeLogin
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                if(error.hasError) {
                    dispatch(hasNoError());
                }
                navigate('/home');
            } 
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            dispatch(hasError(error.response.data.message));
        });
    };

    const handleSubmitGoogleAuthenticator = (values: valuesGoogleSubmitType) => {
        const {googleAuthenticatorCodeLogin} = values;
        const sanitizedGoogleAuthenticatorCodeLogin = DOMPurify.sanitize(googleAuthenticatorCodeLogin);
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/google-authenticator-code-login`, {
            googleAuthenticatorCodeLogin: sanitizedGoogleAuthenticatorCodeLogin
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                if(error.hasError) {
                    dispatch(hasNoError());
                }
                navigate('/home');
            } 
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            dispatch(hasError(error.response.data.message));
        });
    }

    const handleLogout = () => {
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/verification-code-login/logout`)
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                if(error.hasError) {
                    dispatch(hasNoError());
                }
                navigate('/login');
            } 
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            dispatch(hasError(error.response.data.message));
        });
    }

    const switchFormToGoogleAuthenticatorForm = () => {
        setUseGoogleAuthenticatorForm(true);
    }

    const switchSendVerificationCodeForm = () => {
        setUseGoogleAuthenticatorForm(false);
    }
    
    useEffect(() => {
        if(authenticatedUser.hasGoogleAuthenticator) {
            setShowButtonDisplayGoogleAuthenticatorForm(true);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    return (
        <>
            { !useGoogleAuthenticatorForm && 
            <>
                <Layout>
                    <header className={`${style.header}`}>
                        <div className={`${style.logo_container}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </div>
                        <div className={`${style.nav_links}`}>
                            <img className={`${style.profile_picture} rounded-sm`} src={authenticatedUser.profilePicture} alt="nothing" width="25" /> &nbsp; {authenticatedUser.username}
                            <span onClick={handleLogout} className={`${style.link}`}>Logout</span>
                        </div>
                    </header>
                    
                    
                    <main className={`${style.main}`}>
                        <div className={`${style.login_verification_code_form}`}>
                        <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                            <Form>
                                <h1 className={`${style.login_verification_code_form_title}`}>MFA - Login Code</h1>
                                <p className={`${style.login_verification_code_form_subtitle}`}>Please enter your login code to verify</p>

                                <CustomAlert />

                                <CustomInput className={`${style.login_verification_code_form_input}`} type="text" id="verificationCodeLogin" placeholder='Enter your verification code login' name="verificationCodeLogin" autoComplete="off" />
                                <ErrorMessage name="verificationCodeLogin" component="div" className={`${style.login_verification_code_form_input_error}`}/>

                                <CustomButton className={`${style.login_verification_code_form_submit}`} type="submit">Submit</CustomButton>
                                { showButtonDisplayGoogleAuthenticatorForm && 
                                <>
                                    <button onClick={switchFormToGoogleAuthenticatorForm} className={`${style.button_dark}`} type="button">
                                        Use Google Authenticator
                                    </button>
                                </>}
                            </Form>
                        </Formik>
                        </div>
                    </main>
                </Layout>
            </>
            } 

            { useGoogleAuthenticatorForm && 
            <> 
                <Layout>
                    <header className={`${style.header}`}>
                        <div className={`${style.logo_container}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </div>
                        <div className={`${style.nav_links}`}>
                            <img className={`${style.profile_picture} rounded-sm`} src={authenticatedUser.profilePicture} alt="nothing" width="25" /> &nbsp; {authenticatedUser.username}
                            <span onClick={handleLogout} className={`${style.link}`}>Logout</span>
                        </div>
                    </header>

                    <main className={`${style.main}`}>
                        <div className={`${style.login_verification_code_form}`}>
                        <Formik initialValues={initialValuesGoogleAuthenticator} validationSchema={validationSchemaGoogleAuthenticator} onSubmit={handleSubmitGoogleAuthenticator}>
                            <Form>
                                <h1 className={`${style.login_verification_code_form_title}`}>Google Authenticator Code</h1>
                                <p className={`${style.login_verification_code_form_subtitle}`}>Please enter your 6-digit code to verify</p>
                                
                                <CustomAlert /> 

                                <CustomInput className={`${style.login_verification_code_form_input}`} type="text" id="googleAuthenticatorCodeLogin" placeholder='Enter your 6-digit code login' name="googleAuthenticatorCodeLogin" autoComplete="off" />
                                <ErrorMessage name="googleAuthenticatorCodeLogin" component="div" className={`${style.login_verification_code_form_input_error}`}/>

                                <CustomButton className={`${style.login_verification_code_form_submit}`} type="submit">Submit</CustomButton>
                                <button onClick={switchSendVerificationCodeForm} className={`${style.button_dark}`} type="button">
                                    Send Verification Code
                                </button>
                            </Form>
                        </Formik>
                        </div>
                    </main>
                </Layout>
            </>
            }
        </>
    )
}

export default LoginVerificationCode;