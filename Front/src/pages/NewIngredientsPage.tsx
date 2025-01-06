// src/pages/NewIngredientsPage.tsx

import React, { useState } from "react";
import HomeNavBar from "../components/organisms/HomeNavBar";
import { Ingredient } from "../types/EntityTypes";
import EditIngredientModal from "../features/NewIngredients/EditIngredientModal";
import IngredientModal from "../features/NewIngredients/IngredientModal";
import RecognitionResultModal from "../features/NewIngredients/RecognitionResultModal";
import LoadingModal from "../components/organisms/LoadingModal";
import { usePopupState } from "../hooks/usePopupState";
import CategoryTabs from "../features/NewIngredients/CategoryTabs";
import IngredientCard from "../features/NewIngredients/IngredientCard";

const NewIngredientsPage: React.FC = () => {
  const ingredientModal = usePopupState<{ selectedFile: File | null }>({ selectedFile: null });
  const recognitionModal = usePopupState<{ resultList: Ingredient[] }>({ resultList: [] });
  const editModal = usePopupState<Ingredient | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const [ingredients, setIngredients] = useState<Ingredient[]>([
    { ingredientId: 1, name: "토마토", categoryId: 1, storageMethodId: 1, quantity: 10, shelfLife: 7, consumeBy: 14, purchaseDate: "2025-01-01" },
    { ingredientId: 2, name: "방울 토마토", categoryId: 1, storageMethodId: 1, quantity: 20, shelfLife: 7, consumeBy: 14, purchaseDate: "2025-01-03" },
    { ingredientId: 3, name: "김치", categoryId: 2, storageMethodId: 1, quantity: 5, shelfLife: 30, consumeBy: 180, purchaseDate: "2025-01-01" },
  ]);

  const categories = ["전체", "채소", "가공식품"];
  const [activeTab, setActiveTab] = useState<string>("전체");

  // 필터링된 식재료
  const filteredIngredients =
    activeTab === "전체"
      ? ingredients
      : ingredients.filter((item) => item.categoryId === categories.indexOf(activeTab));

  const handleAddIngredient = (newIngredients: Ingredient[]) => {
    setIngredients((prev) => [...prev, ...newIngredients]);
    recognitionModal.close();
  };

  const handleCardClick = (ingredient: Ingredient) => {
    editModal.setState(ingredient);
    editModal.open();
  };

  const handleSave = (updatedIngredient: Ingredient) => {
    setIngredients((prev) =>
      prev.map((ingredient) =>
        ingredient.ingredientId === updatedIngredient.ingredientId
          ? updatedIngredient
          : ingredient
      )
    );
    editModal.close();
  };

  const handleUploadConfirm = () => {
    const { selectedFile } = ingredientModal.state;

    if (!selectedFile) {
      alert("사진을 선택해주세요.");
      return;
    }

    setLoading(true);

    setTimeout(() => {
      setLoading(false);
      const mockResponse: Ingredient[] = [
        { ingredientId: Date.now(), name: "Mock Ingredient 1", quantity: 1, categoryId: 1, storageMethodId: 1, shelfLife: 7, consumeBy: 14, purchaseDate: "2025-01-01" },
      ];
      recognitionModal.setState({ resultList: mockResponse });
      ingredientModal.close();
      recognitionModal.open();
    }, 3000);
  };

  return (
    <div className="container-fluid px-0" style={{ paddingBottom: "var(--navbar-height)" }}>
      <h2 className="text-center my-4">나의 식재료</h2>

      {/* 상단 탭 메뉴 및 등록 버튼 */}
      <CategoryTabs
        categories={categories}
        activeTab={activeTab}
        onTabClick={setActiveTab}
        onAddClick={ingredientModal.open}
      />

      {/* 식재료 카드 리스트 */}
      <div
        className="container justify-content-center"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "1rem",
          justifyContent: "center",
        }}
      >
        {filteredIngredients.map((ingredient) => (
          <IngredientCard
            key={ingredient.ingredientId}
            ingredient={ingredient}
            onClick={() => handleCardClick(ingredient)}
          />
        ))}
      </div>

      {/* 로딩 모달 */}
      {loading && <LoadingModal />}

      {/* 식재료 추가 모달 */}
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

      {/* 인식 결과 모달 */}
      {recognitionModal.isOpen && (
        <RecognitionResultModal
          resultList={recognitionModal.state.resultList}
          onConfirm={handleAddIngredient}
          onClose={recognitionModal.close}
        />
      )}

      {/* 수정 모달 */}
      {editModal.isOpen && editModal.state && (
        <EditIngredientModal
          row={{
            name: editModal.state.name,
            quantity: editModal.state.quantity,
            category: `카테고리 ID: ${editModal.state.categoryId}`,
            storage: `보관 방법 ID: ${editModal.state.storageMethodId}`,
            purchaseDate: editModal.state.purchaseDate || "",
          }}
          onSave={(updatedRow) =>
            handleSave({
              ...editModal.state!,
              name: updatedRow.name,
              quantity: updatedRow.quantity,
              purchaseDate: updatedRow.purchaseDate,
            })
          }
          onCancel={editModal.close}
        />
      )}

      <HomeNavBar />
    </div>
  );
};

export default NewIngredientsPage;
