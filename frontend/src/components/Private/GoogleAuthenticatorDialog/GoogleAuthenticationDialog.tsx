import { useEffect, useState, Fragment, forwardRef } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import axios from 'axios';
import { Dialog, Transition } from '@headlessui/react';
import Box from '@mui/material/Box';
import Snackbar from '@mui/material/Snackbar';
import MuiAlert, { AlertProps } from '@mui/material/Alert';

import { useDispatch } from 'react-redux';
import { setDisable, setNotDisable } from '../../../actions';

import CustomButton from '../../AllRoutes/CustomButton/CustomButton';

// * PART OF SNACKBAR ALERT
const Alert = forwardRef<HTMLDivElement, AlertProps>(function Alert(props,ref) {
  return <MuiAlert elevation={6} ref={ref} variant="filled" {...props} />;
});

interface State {
    message: string;
    open: boolean;
    isSuccess: boolean;
}
// * END PART OF SNACKBAR ALERT

interface GoogleAuthenticatorDialogProps {
    isOpen: boolean;
    handleClose: () => void;
}

const GoogleAuthenticatorDialog = ({isOpen, handleClose}: GoogleAuthenticatorDialogProps) => {
    const navigate = useNavigate();
    const [userGoogleAuthenticatorQRCode, setUserGoogleAuthenticatorQRCode] = useState(undefined);
    const [showEnableGoogleAuthenticatorButton, setShowEnableGoogleAuthenticatorButton] = useState(false);
    const [showDisableGoogleAuthenticatorButton, setShowDisableGoogleAuthenticatorButton] = useState(false);
    const [user]:any = useOutletContext();
    const dispatch = useDispatch();
    
    // * PART OF SNACKBAR ALERT
    const [state, setState] = useState<State>({
        message: '',
        open: false,
        isSuccess: true
    });
    const { open } = state;
    // * END PART OF SNACKBAR ALERT

    function handleEnableGoogleAuthenticator() {
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/enable-google-authenticator`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                // * PART OF SNACKBAR ALERT
                setState({message: 'Successfully enable Google Authenticator', open: true, isSuccess: true});
                // * END PART OF SNACKBAR ALERT
                setUserGoogleAuthenticatorQRCode(response.data.qr_code);
                setShowEnableGoogleAuthenticatorButton(false);
            }
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            // * PART OF SNACKBAR ALERT
            setState({message: 'error.response.data.message', open: true, isSuccess: true});
            // * END PART OF SNACKBAR ALERT
            navigate('/login');
        });
    }

    function handleActivateGoogleAuthenticator() {
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/activate-google-authenticator`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                // * PART OF SNACKBAR ALERT
                setState({message: 'Successfully activate Google Authenticator', open: true, isSuccess: true});
                // * END PART OF SNACKBAR ALERT
                setUserGoogleAuthenticatorQRCode(undefined);
                setShowDisableGoogleAuthenticatorButton(true);   
            }
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            // * PART OF SNACKBAR ALERT
            setState({message: error.response.data.message, open: true, isSuccess: true});
            // * END PART OF SNACKBAR ALERT
            navigate('/login');
        });
    }

    function handleDisableGoogleAuthenticator() {
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/disable-google-authenticator`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                // * PART OF SNACKBAR ALERT
                setState({message: 'Successfully disable Google Authenticator', open: true, isSuccess: true});
                // * END PART OF SNACKBAR ALERT
                setShowEnableGoogleAuthenticatorButton(true);
                setShowDisableGoogleAuthenticatorButton(false);
            }
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            // * PART OF SNACKBAR ALERT
            setState({message: error.response.data.message, open: true, isSuccess: true});
            // * END PART OF SNACKBAR ALERT
            navigate('/login');
        });
    }

    useEffect(() => {
        if(!user.hasOwnProperty('googleAuthenticator')) {
            setShowEnableGoogleAuthenticatorButton(true);
        }

        if(user.hasOwnProperty('googleAuthenticator') && !user.googleAuthenticator.isActivated) {
            setUserGoogleAuthenticatorQRCode(user.googleAuthenticator.qr_code);
        }

        if(user.hasOwnProperty('googleAuthenticator') && user.googleAuthenticator.isActivated) {
            setShowDisableGoogleAuthenticatorButton(true);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <>
            {!user.isSSO &&
                <Transition appear show={isOpen} as={Fragment}>
                    <Dialog as="div" className="relative z-10" onClose={() => {}}>
                        <Transition.Child as={Fragment}
                            enter="ease-out duration-300"
                            enterFrom="opacity-0"
                            enterTo="opacity-100"
                            leave="ease-in duration-200"
                            leaveFrom="opacity-100"
                            leaveTo="opacity-0"
                        >
                            <div className="fixed inset-0 bg-black bg-opacity-25" />
                        </Transition.Child>

                        <div className="fixed inset-0 overflow-y-auto">
                            <div className="flex min-h-full items-center justify-center p-4 text-center">
                            <Transition.Child as={Fragment}
                                enter="ease-out duration-300"
                                enterFrom="opacity-0 scale-95"
                                enterTo="opacity-100 scale-100"
                                leave="ease-in duration-200"
                                leaveFrom="opacity-100 scale-100"
                                leaveTo="opacity-0 scale-95"
                            >
                                <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">
                                <Dialog.Title as="h3"className="text-lg font-medium leading-6 text-gray-900">MFA Google Authenticator</Dialog.Title>
                                <div className="mt-2">
                                    <p className="text-sm text-gray-500">
                                        You can add more security to your account by adding google authenticator.
                                    </p>
                                </div>

                                <div className="mt-4">
                                    {
                                        showEnableGoogleAuthenticatorButton ? 
                                        <CustomButton
                                            type="button"
                                            className="flex content-center justify-center mt-2 mr-2 inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                            style={{alignItems: "center"}}
                                            onClick={handleEnableGoogleAuthenticator}
                                            >
                                            Enable Google Authenticator
                                        </CustomButton> : userGoogleAuthenticatorQRCode !== undefined ?
                                        <div>
                                            <div>
                                                <img src={userGoogleAuthenticatorQRCode}  alt="User Google Authenticator QR Code"/>
                                            </div>
                                            <CustomButton
                                                type="button"
                                                className="mt-2 inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                                style={{alignItems: "center"}}
                                                onClick={handleActivateGoogleAuthenticator}
                                                >
                                                Activate Google Authenticator
                                            </CustomButton>
                                        </div> :
                                        showDisableGoogleAuthenticatorButton ?
                                        <CustomButton
                                            type="button"
                                            className="flex content-center justify-center mt-2 mr-2 inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                            style={{alignItems: "center"}}
                                            onClick={handleDisableGoogleAuthenticator}
                                            >
                                            Disable Google Authenticator
                                        </CustomButton> : <></>
                                    }
                                    <CustomButton
                                        type="button"
                                        className="flex content-center justify-center mt-2 justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                        style={{alignItems: "center"}}
                                        onClick={() => {handleClose()}}
                                        >
                                        Go back
                                    </CustomButton>
                                </div>
                                </Dialog.Panel>
                            </Transition.Child>
                            </div>
                        </div>
                    </Dialog>
                </Transition>
            }

            {/* // * PART OF SNACKBAR ALERT */}
            <Box sx={{ width: 500 }}>
                <Snackbar anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }} open={open} onClose={() => {setState({message: '', open: false, isSuccess: true});}} message={state.message}>
                    <Alert onClose={handleClose} severity={state.isSuccess ? "success" : "error"} sx={{ width: '100%' }}>
                        {state.message}
                    </Alert>
                </Snackbar>
            </Box>
            {/* // * END PART OF SNACKBAR ALERT */}
        </>
    )
}

export default GoogleAuthenticatorDialog;