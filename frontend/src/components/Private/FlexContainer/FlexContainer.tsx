import { ReactNode } from 'react';
import style from './FlexContainer.module.css';

interface FlexContainerProps {
    children: ReactNode;
}

const FlexContainer = ({children}: FlexContainerProps) => {
    return (
        <div className={`${style.flex_container}`}>
            {children}
        </div>
    )
}

export default FlexContainer;