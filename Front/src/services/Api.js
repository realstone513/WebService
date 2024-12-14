// src/services/Api.js
import axios from 'axios';
import { getAccessToken, initializeAccessToken } from './TokenManager';

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

// 응답 인터셉터
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      console.warn("Access Token 만료 감지. 갱신 시도");
      originalRequest._retry = true;

      try {
        const newToken = await initializeAccessToken(api);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        console.error("Access Token 갱신 실패:", refreshError.message);
        return Promise.reject(refreshError);
      }
    }

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
