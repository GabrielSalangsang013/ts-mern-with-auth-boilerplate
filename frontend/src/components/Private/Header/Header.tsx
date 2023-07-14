import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import style from './Header.module.css';
import logo from '../../../assets/logo-header.png';
import HeaderDropdown from '../../../components/Private/HeaderDropdown/HeaderDropdown';
import FlexContainer from '../../../components/Private/FlexContainer/FlexContainer';

import { useDispatch } from 'react-redux';
import { setDisable, setNotDisable } from '../../../actions';

const Header = () => {
    const navigate = useNavigate();
    const dispatch = useDispatch();

    function handleLogout() {
        dispatch(setDisable());
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/logout`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                navigate('/login');
            }
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            navigate('/login');
        });
    }

    function handleDeleteUser() {
        dispatch(setDisable());
        axios.delete(`${process.env.REACT_APP_API}/api/v1/authentication/user`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                dispatch(setNotDisable());
                navigate('/login');
            }
        })
        .catch(function (error) {
            dispatch(setNotDisable());
            navigate('/login');
        });
    }

    return (
        <header className={`${style.header}`}>
            <FlexContainer>
                <div className={`${style.flex_header_container}`}>
                    <div className={`${style.logo_container}`}>
                        <img className={`${style.logo}`} src={logo} alt="Logo" />
                    </div>
                    <HeaderDropdown handleLogout={() => { handleLogout() }} handleDeleteUser={() => handleDeleteUser()}/>
                </div>
            </FlexContainer>
        </header>
    )
}

export default Header;