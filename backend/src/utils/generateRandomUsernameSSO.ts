function generateRandomUsernameSSO() {
    const validChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
    const minLength = 8;
    const maxLength = 8;
  
    let username = '';
    const usernameLength = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  
    for (let i = 0; i < usernameLength; i++) {
      const randomIndex = Math.floor(Math.random() * validChars.length);
      username += validChars.charAt(randomIndex);
    }
  
    return username;
}

export default generateRandomUsernameSSO;