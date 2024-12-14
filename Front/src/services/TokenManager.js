// src/services/TokenManager.js

let accessToken = null;
  
export const getAccessToken = () => {
    console.log('Access Token 조회:', accessToken);
    return accessToken;
  };

export const setAccessToken = (token) => {
    console.log('Access Token 설정:', token);
    accessToken = token;
  };
  
  export const clearAccessToken = () => {
    console.log('Access Token 제거');
    accessToken = null;
  };

// Access Token 갱신 함수
export const refreshAccessToken = async (api) => {
    try {
      console.log('Access Token 갱신 요청 시작');
      const response = await api.post('/auth/refresh', { refreshToken: true });
      const newAccessToken = response.data.accessToken;
  
      console.log('Access Token 갱신 성공:', newAccessToken);
      setAccessToken(newAccessToken);
  
      return newAccessToken;
    } catch (error) {
      if (error.response?.status === 401 && error.response?.data?.tokenType === 'refresh') {
        console.error('Refresh Token 만료: 사용자 로그아웃 필요');
        clearAccessToken();
        throw new Error('Refresh Token이 만료되었습니다. 다시 로그인하세요.');
      }
      console.error('Access Token 갱신 실패:', error.message);
      throw error;
    }
  };
  