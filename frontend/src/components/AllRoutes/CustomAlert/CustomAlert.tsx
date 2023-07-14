import Alert from '@mui/material/Alert';
import Stack from '@mui/material/Stack';
import { useSelector } from 'react-redux';
import { AllReducers } from '../../../interfaces';

const CustomAlert = () => {
  const error = useSelector((state: AllReducers) => state.error);

  if(!error.hasError) {
    return (
      <></>
    )
  }

  return (
    <>
      <Stack className='mb-2' sx={{ width: '100%' }} spacing={2}>
        <Alert variant="filled" severity="error">
          { error.errorMessage }
        </Alert>
      </Stack>
    </>
  );
}

export default CustomAlert;
