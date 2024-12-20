// src/pages/MyIngredientsPage.js

import React, { useState } from "react";
import IngredientModal from "../features/MyIngredients/IngredientModal";
import RecognitionResultModal from "../features/MyIngredients/RecognitionResultModal";
import LoadingModal from "../components/organisms/LoadingModal";
import IngredientsTable from "../features/MyIngredients/IngredientsTable";
import { usePopupState } from "../hooks/usePopupState";
import { Plus } from "react-bootstrap-icons";
import HomeNavBar from "../components/organisms/HomeNavBar";

const getRandomIngredients = (ingredients, count) => {
  const shuffled = [...ingredients].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, count).map((item) => ({ name: item, quantity: 1 }));
};

const MyIngredientsPage = () => {
  const ingredientModal = usePopupState({ selectedFile: null });
  const recognitionModal = usePopupState({ resultImage: null, resultList: [] });
  const [loading, setLoading] = useState(false);
  const [dataFrame, setDataFrame] = useState([]);

  const ingredientList = [
    "당근", "계란", "마늘", "감자", "생닭고기", "생 소고기", "밥", "고구마", "두부", "토마토",
    "대파", "고등어", "김치", "돼지고기", "양배추", "버섯", "콩나물", "애호박", "고추", "깻잎",
    "시리얼", "김", "라면", "참치캔", "냉동 만두", "베이컨", "시금치", "오이", "게맛살", "삼겹살"
  ];

  const categories = ["채소", "육류", "가공식품", "발효식품", "과일"];
  const storageMethods = ["냉장", "냉동", "상온"];

  const handleUploadConfirm = () => {
    const { selectedFile } = ingredientModal.state;

    if (!selectedFile) {
      alert("사진을 선택해주세요.");
      return;
    }

    setLoading(true);

    setTimeout(() => {
      setLoading(false);

      const randomCount = Math.floor(Math.random() * 5) + 4;
      const randomIngredients = getRandomIngredients(ingredientList, randomCount);

      recognitionModal.setState({
        resultImage: selectedFile,
        resultList: randomIngredients,
      });

      ingredientModal.close();
      recognitionModal.open();
    }, 3000);
  };

  const handleRecognitionConfirm = (editedIngredients) => {
    const combinedData = editedIngredients.map((item) => ({
      ...item,
      shelfLife: `${Math.floor(Math.random() * 10) + 1}일`,
      consumeBy: `${Math.floor(Math.random() * 15) + 5}일`,
      category: categories[Math.floor(Math.random() * categories.length)],
      storage: storageMethods[Math.floor(Math.random() * storageMethods.length)],
    }));

    setDataFrame((prev) => [...prev, ...combinedData]);
    recognitionModal.close();
    recognitionModal.reset();
  };

  return (
    <div className="container text-center my-ingredients">
      <h2 className="my-3">나의 식재료</h2>

      {ingredientModal.isOpen && (
        <IngredientModal
          onConfirm={handleUploadConfirm}
          onCancel={ingredientModal.close}
          selectedFile={ingredientModal.state.selectedFile}
          fileChangeHandler={(file) =>
            ingredientModal.setState({ ...ingredientModal.state, selectedFile: file })
          }
        />
      )}

      {recognitionModal.isOpen && (
        <RecognitionResultModal
          result={recognitionModal.state}
          onConfirm={handleRecognitionConfirm}
          onClose={recognitionModal.close}
        />
      )}

      {loading && <LoadingModal />}

      <IngredientsTable
        data={dataFrame}
        onSaveRow={(index, updatedRow) =>
          setDataFrame((prevData) =>
            prevData.map((item, i) => (i === index ? updatedRow : item))
          )
        }
        onDeleteRow={(index) =>
          setDataFrame((prevData) => prevData.filter((_, i) => i !== index))
        }
      />

      <button
        className="btn btn-success position-fixed"
        style={{
          bottom: "80px",
          right: "20px",
          width: "56px",
          height: "56px",
          borderRadius: "50%",
        }}
        onClick={() => {
          ingredientModal.reset();
          ingredientModal.open();
        }}
      >
        <Plus size={28} />
      </button>

      <HomeNavBar />
    </div>
  );
};

export default MyIngredientsPage;
