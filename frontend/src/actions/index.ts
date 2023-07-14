export const setDisable = () => {
    return {
        type: 'SET_DISABLE'
    }
}

export const setNotDisable = () => {
    return {
        type: 'SET_NOT_DISABLE'
    }
}

export const hasError = (errorMessage: string) => {
    return {
        type: 'HAS_ERROR',
        errorMessage: errorMessage
    }
}

export const hasNoError = () => {
    return {
        type: 'HAS_NO_ERROR'
    }
}