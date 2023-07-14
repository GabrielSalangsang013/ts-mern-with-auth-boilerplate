import { ReactNode } from 'react';
import style from './Layout.module.css';
import { useSelector } from 'react-redux';
import { AllReducers } from '../../../interfaces';

interface LayoutProps {
    children: ReactNode;
}

const Layout = ({children}: LayoutProps) => {
    const isDisabled = useSelector((state: AllReducers) => state.isDisabled);

    return (
        <>
            <div className={`${style.container} ${isDisabled && 'disabled'}`}>
                {children}
            </div>
        </>
    )
}

export default Layout;