"""Permit multiple TOTP authenticators to be used per individual account.

Revision ID: 19bf9ceaa459
Revises: b194ab27295e
Create Date: 2018-07-04 20:10:31.851661

"""

# revision identifiers, used by Alembic.
revision = '19bf9ceaa459'
down_revision = 'b194ab27295e'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('twofa_totp_secrets',
        sa.Column('userid', sa.Integer(), nullable=False),
        sa.Column('totp_secret', sa.String(length=420), nullable=False),
        sa.Column('comment', sa.String(length=100), server_default='', nullable=False),
        sa.Column('createtimestamp', sa.DateTime(timezone=True), server_default=sa.text(u'now()'), nullable=False),
        sa.ForeignKeyConstraint(['userid'], ['login.userid'], name='twofa_totp_secrets_userid_fkey', onupdate='CASCADE', ondelete='CASCADE')
    )

    op.create_index('ind_twofa_totp_secrets_userid', 'twofa_totp_secrets', ['userid'], unique=False)

    op.add_column(u'login', sa.Column('twofa_totp_enabled', sa.Boolean(), server_default='f', nullable=False))

    # Set that TOTP is enabled...
    op.execute("""
        UPDATE login
        SET twofa_totp_enabled = TRUE
        WHERE twofa_secret IS NOT NULL
    """)

    # Copy over the TOTP secret...
    op.execute("""
        INSERT INTO twofa_totp_secrets AS ts (userid, totp_secret)
            SELECT lo.userid, lo.twofa_secret
            FROM login AS lo
            WHERE lo.twofa_secret IS NOT NULL
    """)

    op.drop_column(u'login', 'twofa_secret')
    # ### end Alembic commands ###


def downgrade():
    # TODO: Irreversable migration this... only other option would be keep the newest TOTP secret.

    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(u'login', sa.Column('twofa_secret', sa.VARCHAR(length=420), autoincrement=False, nullable=True))
    op.drop_column(u'login', 'twofa_totp_enabled')
    op.drop_index('ind_twofa_totp_secrets_userid', table_name='twofa_totp_secrets')
    op.drop_table('twofa_totp_secrets')
    # ### end Alembic commands ###
