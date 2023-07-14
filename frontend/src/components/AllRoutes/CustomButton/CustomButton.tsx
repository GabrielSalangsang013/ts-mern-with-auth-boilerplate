import { ReactNode, ButtonHTMLAttributes, forwardRef } from 'react';
import { useSelector } from 'react-redux';
import { AllReducers } from '../../../interfaces';
import SpinnerCircleDark from '../../../assets/spinner-circle-dark.svg';

interface CustomButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode;
}

const CustomButton = forwardRef<HTMLButtonElement, CustomButtonProps>(({ children, ...props }, ref) => {
    const isDisabled = useSelector((state: AllReducers) => state.isDisabled);

    return (
      <button ref={ref} disabled={isDisabled} {...props}>
        {isDisabled && <img width={15} style={{marginRight:'10px'}} src={SpinnerCircleDark} alt="none" />}
        {children}
      </button>
    );
  }
);

export default CustomButton;
