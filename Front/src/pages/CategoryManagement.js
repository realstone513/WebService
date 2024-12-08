// src/pages/CategoryManagement.js
import React, { useState } from 'react';
import { useAdminContext } from '../contexts/AdminContext';
import { Container, Form, Button, Table } from 'react-bootstrap';
import AdminNavBar from '../components/organisms/AdminNavBar';

function CategoryManagement() {
  const { categories, handleAddCategory, handleDeleteCategory } = useAdminContext();
  const [newCategoryName, setNewCategoryName] = useState("");

  const handleAdd = (event) => {
    event.preventDefault();
    if (!newCategoryName.trim()) {
      alert("카테고리 이름을 입력해 주세요.");
      return;
    }
    handleAddCategory(newCategoryName);
    setNewCategoryName("");
  };

  return (
    <>
      <AdminNavBar />
      <Container className="mt-4">
        <h3>카테고리 관리</h3>
        <Form onSubmit={handleAdd} className="mb-3">
          <Form.Group>
            <Form.Label>카테고리 이름</Form.Label>
            <Form.Control
              type="text"
              value={newCategoryName}
              onChange={(e) => setNewCategoryName(e.target.value)}
              placeholder="새 카테고리 이름"
            />
        </Form.Group>
        <Button variant="primary" type="submit" className="mt-3">
          추가
        </Button>
      </Form>

      <Table striped bordered hover>
        <thead>
          <tr>
            <th>ID</th>
            <th>카테고리 이름</th>
            <th>삭제</th>
          </tr>
        </thead>
        <tbody>
          {categories.map((category) => (
            <tr key={category.id}>
              <td>{category.id}</td>
              <td>{category.categoryName}</td>
              <td>
                <Button
                  variant="danger"
                  onClick={() => handleDeleteCategory(category.id)}
                >
                  삭제
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Container>
    </>
  );
}

export default CategoryManagement;
