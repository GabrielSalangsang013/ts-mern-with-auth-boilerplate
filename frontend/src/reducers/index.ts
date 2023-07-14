import { combineReducers } from 'redux';

// * ALL REDUCERS
import isDisableReducer from './isDisableReducer';
import errorReducer from './errorReducer';
// * END ALL REDUCERS

const allReducers = combineReducers({
    isDisabled: isDisableReducer,
    error: errorReducer
})

export default allReducers;