import { ReactNode } from 'react';
import { Link, LinkProps } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { AllReducers } from '../../../interfaces';
import { hasNoError } from '../../../actions';

interface CustomLinkProps extends LinkProps {
  children: ReactNode;
}

const CustomLink = ({ children, ...props }: CustomLinkProps) => {
  const isDisabled = useSelector((state: AllReducers) => state.isDisabled);
  const dispatch = useDispatch();

  return (
    <Link onClick={() => dispatch(hasNoError())} className={isDisabled ? 'disabled' : ''} {...props}>
      {children}
    </Link>
  );
}

export default CustomLink;
