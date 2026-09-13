from trytond.pool import PoolMeta
from trytond.transaction import Transaction


class Rule(metaclass=PoolMeta):
    __name__ = 'ir.rule'

    @classmethod
    def _get_context(cls, model_name):
        context = super()._get_context(model_name)
        if model_name == 'res.user.webauthn.credential':
            context['user_id'] = Transaction().user
        return context

    @classmethod
    def _get_cache_key(cls, model_names):
        key = super()._get_cache_key(model_names)
        if 'res.user.webauthn.credential' in model_names:
            key = (*key, Transaction().user)
        return key
