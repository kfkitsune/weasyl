"""Verify email addresses before changing.

Leverage the existing `emailverify` table (which was unused) to store an email prior to changing
the email on an account, requiring the user to provide a token to confirm ownership of the email
before changing the email on the user's account.

Revision ID: f5ff61d4d4d9
Revises: 40c00abab5f9
Create Date: 2017-03-05 04:04:19.732220

"""

# revision identifiers, used by Alembic.
revision = 'f5ff61d4d4d9'
down_revision = '40c00abab5f9'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('emailverify',
        sa.Column('createtimestamp', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=False)
    )
    op.add_column('emailverify',
        sa.Column('token', sa.String(length=100), nullable=False)
    )


def downgrade():
    op.drop_column('emailverify', 'token')
    op.drop_column('emailverify', 'createtimestamp')
