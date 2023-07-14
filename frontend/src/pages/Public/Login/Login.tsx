import { useNavigate } from 'react-router-dom';
import { Formik, Form, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './Login.module.css';
import FirebaseGoogleSignInButton from '../../../components/Public/FirebaseGoogleSignInButton/FirebaseGoogleSignInButton';
import FirebaseFacebookSignInButton from '../../../components/Public/FirebaseFacebookSignInButton/FirebaseFacebookSignInButton';
import GoogleIdentityServices from '../../../components/Public/GoogleIdentityServices/GoogleIdentityServices';
import logo from '../../../assets/logo-header.png';

import { useSelector, useDispatch } from 'react-redux';
import { setDisable, setNotDisable, hasError, hasNoError } from '../../../actions';
import { AllReducers } from '../../../interfaces';

import CustomButton from '../../../components/AllRoutes/CustomButton/CustomButton';
import CustomAlert from '../../../components/AllRoutes/CustomAlert/CustomAlert';
import CustomInput from '../../../components/AllRoutes/CustomInput/CustomInput';
import CustomLink from '../../../components/AllRoutes/CustomLink/CustomLink';
import Layout from '../../../components/AllRoutes/Layout/Layout';

type valuesType = {
    username: string,
    password: string
}

const Login = () => {
    const navigate = useNavigate();    
    const error = useSelector((state: AllReducers) => state.error);
    const dispatch = useDispatch();

    const initialValues = {
        username: '',
        password: ''
    };

    const validationSchema = Yup.object().shape({
        username: Yup.string()
            .required('Username is required')
            .trim()
            .min(4, 'Username must be at least 4 characters')
            .max(20, 'Username must not exceed 20 characters')
            .matches(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
            .test(
                'username-security',
                'Username should not contain sensitive information',
                (value) => !/\b(admin|root|superuser)\b/i.test(value)
            )
            .test(
                'username-xss-nosql',
                'Invalid characters detected',
                (value) => {
                    const sanitizedValue = escape(value);
                    return sanitizedValue === value; // Check if sanitized value is the same as the original value
                }
            ),
        password: Yup.string()
            .required('Password is required')
            .min(12, 'Password must be at least 12 characters')
            .matches(
                /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/,
                'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character'
            )
            .test(
                'password-security',
                'Password should not be commonly used or easily guessable',
                (value) => !/\b(password|123456789)\b/i.test(value)
            )
    });

    const handleSubmit = (values:valuesType) => {
        const {username, password} = values;
        const sanitizedLoginUsername = DOMPurify.sanitize(username);
        const sanitizedLoginPassword = DOMPurify.sanitize(password);
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/login`, {
            username: sanitizedLoginUsername,
            password: sanitizedLoginPassword
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                if(error.hasError) {
                    dispatch(hasNoError());
                }
                navigate('/login/multi-factor-authentication');
            } 
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            dispatch(hasError(error.response.data.message));
        });
    };

    return (
        <>
            <Layout>
                <header className={`${style.header}`}>
                    <div className={`${style.logo_container}`}>
                        <CustomLink to='/' className={`${style.link}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </CustomLink>
                    </div>
                    <div className={`${style.nav_links}`}>
                        <CustomLink to='/register' className={`${style.link}`}>Register</CustomLink>
                    </div>
                </header>
                
                <main className={`${style.main}`}>
                    <div className={`${style.login_form}`}>
                        <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                            <Form>
                                <h1 className={`${style.login_form_title}`}>Welcome to Login</h1>
                                <p className={`${style.login_form_subtitle}`}>Enter your username and password to login</p>

                                <CustomAlert />

                                <CustomInput className={`${style.login_form_input}`} placeholder='Enter your username' type="text" id="username" name="username"/>
                                <ErrorMessage name="username" component="div" className={`${style.login_form_input_error}`}/>
                                <CustomInput className={`${style.login_form_input}`} placeholder='Enter your password' type="password" id="password" name="password"/>
                                <ErrorMessage name="password" component="div" className={`${style.login_form_input_error}`}/>    
                                <CustomButton className={`${style.login_form_submit}`} type="submit">Sign In</CustomButton>
                                <CustomLink to="/forgot-password" className={`${style.login_form_link_forgot_password}`}>Forgot password?</CustomLink>

                                <div className={`${style.overline_container}`}>
                                    <div className={`${style.overline}`}></div>
                                    <div className={`${style.overline_text}`}>
                                        <span>OR CONTINUE WITH</span>
                                    </div>
                                </div>

                                <GoogleIdentityServices addButton={true} addPrompt={true} text={'signin_with'}/> 
                                <FirebaseFacebookSignInButton text={'signin_with'}/>
                                <FirebaseGoogleSignInButton text={'signin_with'}/>
                            </Form>
                        </Formik>
                    </div>
                </main>
            </Layout>
        </>
    )
}

export default Login;