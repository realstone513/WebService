// src/features/Settings/TeamInfo.tsx

import React, { useState, useEffect } from 'react';

interface TeamMember {
  name: string;
  email: string;
  role: string;
}

const TeamInfo: React.FC = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([]);

  useEffect(() => {
    fetch('Data/TeamMembers.json')
      .then((response) => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json() as Promise<TeamMember[]>;
      })
      .then((data) => setTeamMembers(data))
      .catch((error) => console.error('Error loading team members:', error));
  }, []);

  const openModal = () => setIsModalOpen(true);
  const closeModal = () => setIsModalOpen(false);

  return (
    <>
      <button className="btn btn-primary" onClick={openModal}>
        개발팀 정보
      </button>

      {isModalOpen && (
        <div
          className="modal show d-block"
          tabIndex={-1}
          role="dialog"
          style={{ backgroundColor: 'rgba(0, 0, 0, 0.5)' }}
        >
          <div className="modal-dialog modal-lg" role="document">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">개발팀 정보</h5>
                <button
                  type="button"
                  className="btn-close"
                  aria-label="Close"
                  onClick={closeModal}
                ></button>
              </div>
              <div className="modal-body">
                <div className="row">
                  {teamMembers.map((member, index) => (
                    <div key={index} className="col-12 mb-3">
                      <div className="card shadow-sm">
                        <div className="card-body">
                          <h5 className="card-title">
                            {member.name}{' '}
                            <span className="text-muted">({member.email})</span>
                          </h5>
                          <p className="card-text">{member.role}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={closeModal}
                >
                  닫기
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default TeamInfo;
