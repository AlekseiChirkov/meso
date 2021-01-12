import pandas as pd

from catalog.models import Product


def excel_data_in_model(request):
    file_obj = request.FILES['file'].file
    data = pd.read_excel(file_obj)
    df = pd.DataFrame(data, columns=[
        'Артикул', 'Номенклатура', 'Штрихкод', 'Ед. изм.',
        'Остаток', 'Цена', 'НДС, %'
    ])
    df_list = df.values.tolist()
    df_list = [[str(j) for j in i] for i in df_list]
    rows = [[j for j in i if j != 'nan'] for i in df_list]
    cleaned_rows = [i for i in rows if i]
    for i in cleaned_rows:
        product = Product.objects.create(
            article=str(i[0]),
            nomenclature=str(i[1]),
            bar_code=str(i[2]),
            unit=str(i[3]),
            residue=float(i[4]),
            price=float(i[5]),
            nds=float(i[6])
        )
        product.save()
