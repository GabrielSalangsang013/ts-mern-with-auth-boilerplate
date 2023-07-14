import { InputHTMLAttributes } from 'react';
import { useSelector } from 'react-redux';
import { AllReducers } from '../../../interfaces';
import { Field } from 'formik';

const CustomInput = ({ ...props }: InputHTMLAttributes<HTMLInputElement>) => {
  const isDisabled = useSelector((state: AllReducers) => state.isDisabled);

  return (
    <>
      <Field disabled={isDisabled} {...props} />
    </>
  );
}

export default CustomInput;
