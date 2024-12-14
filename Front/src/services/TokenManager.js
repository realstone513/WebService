// src/services/TokenManager.js

let accessToken = null;

export const getAccessToken = () => accessToken;

export const setAccessToken = (token) => {
  console.log('Access Token 설정:', token);
  accessToken = token;
};

export const clearAccessToken = () => {
  console.log('Access Token 제거');
  accessToken = null;
};

export const initializeAccessToken = async (api) => {
    try {
      console.log("Access Token 초기화 시도");
      const response = await api.post('/auth/refresh', {}, { withCredentials: true });
      setAccessToken(response.data.accessToken);
      console.log("Access Token 초기화 성공");
      return response.data.accessToken;
    } catch (error) {
      console.error("Access Token 초기화 실패:", error.message);
      throw new Error("초기화 실패");
    }
  };