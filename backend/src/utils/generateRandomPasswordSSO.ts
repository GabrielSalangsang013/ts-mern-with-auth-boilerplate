function generateRandomPasswordSSO() {
    const uppercaseLetters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercaseLetters = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const specialCharacters = '!@#$%^&*()_+~`|}{[]\:;?><,./-=';
  
    const minLength = 12;
  
    // * Create an array containing all the required character types
    const requiredCharacters = [
      uppercaseLetters,
      lowercaseLetters,
      digits,
      specialCharacters
    ];
  
    let password = '';
  
    // * Add one character from each required character type
    requiredCharacters.forEach((charType) => {
      const randomIndex = Math.floor(Math.random() * charType.length);
      password += charType.charAt(randomIndex);
    });
  
    // * Add remaining characters randomly
    const remainingLength = minLength - requiredCharacters.length;
  
    for (let i = 0; i < remainingLength; i++) {
      const charType = requiredCharacters[Math.floor(Math.random() * requiredCharacters.length)];
      const randomIndex = Math.floor(Math.random() * charType.length);
      password += charType.charAt(randomIndex);
    }
  
    return password;
}

export default generateRandomPasswordSSO;