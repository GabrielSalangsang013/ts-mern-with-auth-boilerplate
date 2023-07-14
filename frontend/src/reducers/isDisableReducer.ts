type actionType = {
    type: string
}

const isDisableReducer = (state: boolean = false, action: actionType) => {
    switch(action.type) {
        case 'SET_DISABLE':
            return true;
        case 'SET_NOT_DISABLE':
            return false;
        default:
            return state;
    }
}

export default isDisableReducer;