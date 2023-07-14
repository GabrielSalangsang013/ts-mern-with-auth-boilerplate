type stateType = {
    hasError: boolean,
    errorMessage: string
}

type actionType = {
    type: string,
    errorMessage: string
}
const defaultState = {
    hasError: false, 
    errorMessage: ''
}

const errorReducer = (state: stateType = defaultState, action: actionType) => {
    switch(action.type) {
        case 'HAS_ERROR':
            return {
                hasError: true,
                errorMessage: action.errorMessage
            };
        case 'HAS_NO_ERROR':
            return {
                hasError: false,
                errorMessage: ''
            };
        default:
            return state;
    }
}

export default errorReducer;