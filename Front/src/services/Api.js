// src/services/Api.js
import axios from 'axios';
import { getAccessToken, refreshAccessToken } from './TokenManager';

export const api = axios.create({
  baseURL: 'http://localhost:8080/api',
  withCredentials: true,
});

// Authorization Header 생성 함수
export const getAuthHeaders = () => {
  const accessToken = getAccessToken();
  if (!accessToken) {
    console.warn('Access Token이 설정되지 않았습니다.');
    return {}; // 헤더 없이 빈 객체 반환
  }
  return {
    Authorization: `Bearer ${accessToken}`,
  };
};

// Axios 응답 인터셉터 - Access Token 갱신 로직
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    console.log('응답 interceptor 진입: ', error.response?.status);

    if (error.response?.status === 401 && !originalRequest._retry) {
      console.warn('Access Token 만료 감지, 갱신 시도 중'); // 로그 추가
      originalRequest._retry = true;

      try {
        const newToken = await refreshAccessToken(api);
        console.log('Access Token 갱신 성공:', newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        console.error('Access Token 갱신 시도 실패:', refreshError.message);
        return Promise.reject(refreshError);
      }
    }
    // 다른 모든 에러 처리
    console.error('API 요청 에러:', error.message);
    return Promise.reject(error);
  }
);

// 공통적인 에러 핸들링 함수
export const handleApiError = (error, defaultMessage) => {
  if (error.response?.data?.message) {
    console.error('API 오류:', error.response.data.message); // 로그 추가
    return new Error(error.response.data.message);
  }
  console.error('API 오류:', defaultMessage); // 로그 추가
  return new Error(defaultMessage);
};
