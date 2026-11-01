"""initial migration

Revision ID: 001_initial
Revises: 
Create Date: 2026-11-01 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Tables are created via Base.metadata.create_all() or alembic upgrade
    pass

def downgrade() -> None:
    pass

